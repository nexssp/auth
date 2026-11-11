# Host integration and production security

`nexssp/auth` supplies generic authentication use cases; it does not make a deployment secure by itself. Production hosts must provide durable storage, deployment secrets, browser-session policy, rate limits, app-specific registration rules, and authorization. Do not treat successful compilation or a passing test suite as a security review of the host.

## Use the storage-neutral service

Production code should build `auth.Service` with host implementations of `AccountStore`, `HostPolicy`, `BrowserSessionHost`, and `BrowserSessionLifetime`. Add email, one-time-token, OAuth-state, pending-link, desktop-auth, and bearer-token adapters only for features the host actually enables. The `NewService` constructor requires the account store, host policy, browser session host, and session lifetime.

The host must preserve the contracts documented on each interface. In particular, account uniqueness and registration eligibility must be atomic; reset and verification token consumption must be single-use; password changes must revoke existing auth state in one transaction; OAuth state and desktop code exchange must be atomic; and provider identity linking must require the signed-in account's explicit action. Use a database-backed or distributed rate limiter for multi-instance deployments rather than relying on per-process memory.

When an `EmailSender` is configured with reset or verification token storage, that token store must also implement `OneTimeTokenRevoker`. `NewService` rejects email-backed token configurations without revocation. If revocation itself fails after a delivery failure, the service returns both errors; the generic forgot/resend HTTP response remains non-enumerating, so hosts that need operational alerts must monitor this failure through a privacy-safe channel.

The current `Service` contracts are not implemented by the legacy `GORMStore` or `NewMemoryStore`; those implement the older `Store` API. A host that uses `Service` must implement each enabled modern interface and its atomicity guarantees itself. A passing library test suite does not establish correctness of host adapters, database transactions, session cookies, trusted-proxy configuration, or application authorization.

## Reuse the HTTP rate-limit boundary

The package can compose the existing `security/ratelimit` limiter with the host's `RequestBoundary`, so hosts do not need to reimplement rate-limit plumbing. The host still chooses thresholds/backends and supplies `Key`, which must derive caller identity from trusted middleware or a correctly configured proxy chain—not directly from caller-controlled forwarded headers. Use a keyed digest if the backend would otherwise retain personal identifiers. Rate limiting happens before the wrapped boundary; a denial maps to HTTP `429`, and key-derivation or backend failures fail closed with HTTP `503`.

```go
rateLimitedBoundary, err := auth.NewRateLimitedRequestBoundary(hostRequestBoundary, auth.RateLimitConfig{
    Default: ratelimit.NewRedisLimiter(redisClient, 10, 20, "myapp:auth"),
    Operations: map[auth.BoundaryOperation]ratelimit.Limiter{
        auth.BoundaryLogin: ratelimit.NewRedisLimiter(redisClient, 2, 5, "myapp:auth:login"),
    },
    Key: hostAuthRateLimitKey, // host function using trusted client/session identity
})
if err != nil {
    return err
}

handler, err := auth.NewHTTPHandler(auth.HTTPConfig{
    Service:  service,
    Boundary: rateLimitedBoundary,
})
```

The adapter adds an `auth:<operation>:` prefix to each key, so operations have separate buckets even when they share one limiter. `Default` covers every auth operation and `Operations` overrides only the listed ones. Keep request-origin/CSRF checks, Turnstile, terms and registration eligibility in the wrapped host boundary; rate limiting does not replace those controls. For multi-instance deployments, use a shared limiter such as Redis rather than `ratelimit.NewMemoryLimiter`.

For public browser routes, pass `rateLimitedBoundary` to `NewSecureHTTPHandler`; its Turnstile boundary invokes the wrapped boundary first, so rate limiting runs before Siteverify. Use `NewHTTPHandler` directly only when the host supplies equivalent server-side anti-abuse verification itself.

## Require Turnstile on public browser auth

Create Cloudflare Turnstile keys for the exact browser hostname. Configure these values in the host environment or secret manager before creating the HTTP handler or Flow boundary:

```text
TURNSTILE_SITE_KEY=<public site key; browser use only>
TURNSTILE_SECRET_KEY=<server-only secret; never expose to the browser>
TURNSTILE_EXPECTED_HOSTNAME=auth.example.com
```

The host owns environment loading: this library does not parse `.env` files or choose environment variable names. The frontend must load Cloudflare's widget script, render it with the public site key and the matching operation action, and send the challenge response as `turnstile_token`. For example, use action names `login`, `register`, `password_reset`, `email_verify`, `oauth_begin`, and `desktop_start`; email resend shares the `email_verify` action. Do not put response tokens or secret keys in source files, URLs, command arguments, retries, logs, or traces.

Build a verifier once at process startup and use the secure HTTP constructor:

```go
verifier, err := auth.NewCloudflareTurnstileVerifier(auth.CloudflareTurnstileConfig{
    SecretKey:        os.Getenv("TURNSTILE_SECRET_KEY"),
    ExpectedHostname: os.Getenv("TURNSTILE_EXPECTED_HOSTNAME"),
})
if err != nil {
    return err
}

handler, err := auth.NewSecureHTTPHandler(auth.HTTPConfig{
    Service:  service,
    Boundary: hostRequestBoundary,
}, verifier)
if err != nil {
    return err
}
```

`NewSecureHTTPHandler` adds server-side Siteverify checks for login, registration, password forgot/reset, email verification, OAuth begin, and desktop authorization start. It checks `success`, the configured hostname, and the exact action. It does not retry single-use response tokens. The host boundary still must enforce request origin/CSRF, trusted identity, registration eligibility, and rate limits. A Siteverify outage returns a generic retryable `503`; it does not bypass the challenge.

For Flow, construct `nexssflow.NewTurnstileActionBoundary(hostActionBoundary, verifier, auth.DefaultTurnstileOperations()...)` and pass that wrapper to `WithRuntimeDependencies` for every protected execution. Use the same verifier for raw HTTP handlers. If a host chooses a different anti-abuse product or a different set of challenged operations, it may use the lower-level constructors, but must enforce an equivalent server-side check before the auth service consumes credentials.

Follow Cloudflare's [server-side validation guide](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/). Cloudflare's [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) are intended for non-production tests; never use them in a public deployment or infer production readiness from a passing test-key response.

## Sessions, identity, and application authorization

The host owns session-cookie issuance and must rotate the session identifier on login and privilege changes. Set `Secure`, `HttpOnly`, and an appropriate `SameSite` value; scope cookies narrowly; enforce idle and absolute expiry; and implement CSRF protection for cookie-authenticated state changes. The `BrowserSessionHost` is responsible for these behaviors. `HTTPHandler` attaches the active exchange for its own routes; Flow or other host-managed executions must attach it with `WithHTTPExchange`. Use request/response objects only for the current call and never retain or serialize a response writer.

Derive the current account from a validated host session. Never trust caller-supplied identity headers, tenant IDs, workspace IDs, roles, or forwarded-IP headers. Configure the trusted-proxy chain before using client IPs for rate limits. This package does not decide tenant membership, tenant-to-database routing, workspace/project access, roles, or resource permissions; authorize each operation in the host using current server-side state.

## Registration, email, and OAuth

The host `HostPolicy` is responsible for invites, terms acceptance, signup eligibility, first-admin creation, and email-verification mode. Keep those decisions and account persistence in one transaction. The host also owns email templates, sender identity, canonical reset/verification links, delivery retries, abuse throttling, and suppression policy. The generic service avoids revealing whether an account exists for reset and resend requests, but the host must keep timing and delivery behavior from reintroducing an oracle.

Use fixed OAuth callback URLs registered at the provider; never accept a callback destination supplied by the browser. Validate provider configuration, use HTTPS, keep secrets server-side, bind callbacks to one-use state and PKCE, and redact authorization codes, state values, tokens, and callback URLs from logs. Apple `form_post` requires a compatible cross-site cookie policy. Matching provider email alone must not link identities; this package's production service requires an explicit signed-in account-link action.

## Legacy API

`auth.New(Config)` is deprecated and restricted to explicit `dev`, `development`, or `test` environments. It is not a production compatibility path: its legacy behavior does not replace the host-owned service, session, Turnstile, and authorization boundaries. Do not label a public deployment `development` to bypass the restriction. The legacy middleware also no longer accepts credentials from query strings.

The legacy `Store`, `GORMStore`, and `NewMemoryStore` APIs also include older token, OAuth, role, and tenancy behavior; they do not provide the modern `Service` interface or its transactional guarantees. Do not use them as drop-in production persistence for `Service`, and do not treat legacy tenant or role data as application authorization policy.

## AES-GCM encryption helper key

If the host uses the separate `auth/crypto` helper, set `NEXSS_CRYPTO_KEY` before encrypting or decrypting. It must represent exactly 32 key bytes, supplied as raw bytes, 64 hexadecimal characters, or Base64. The package now returns an error when the key is missing or malformed; it no longer provides a fixed development fallback or silently pads/truncates a value. Store the key in a secret manager and do not log or print it.

Before upgrading, identify the effective key used for existing ciphertext. The old helper padded short values with zero bytes and truncated long values to the first 32 bytes; those ciphertexts will only decrypt when the exact old 32-byte effective key is supplied (for example, encoded as 64 hex characters). Plan any conversion/re-encryption under controlled access before rotating the key. Never replace a production key without a tested backup/restore and data-migration plan.
