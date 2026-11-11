# nexssp/auth

<small>Nexss Flow ready</small>

`github.com/nexssp/auth` provides storage-neutral authentication use cases, provider adapters, guarded HTTP routes, a credential-free Kernel session action, and an opt-in Flow bundle. It is not a complete login server or user database; production safety depends on the host's adapters and deployment configuration.

## Included

- Password registration, login, password reset, and optional email verification. Passwords use bcrypt-compatible hashes and a 12–72 byte policy.
- Digest-only, one-use reset and verification tokens, with atomic consume-and-apply guarantees delegated to host stores.
- Host-managed browser sessions, separate from native desktop PKCE handoff codes and opaque bearer credentials.
- Google, GitHub, Apple, and Facebook provider adapters. Facebook uses a manually built OIDC/PKCE flow that Meta currently labels as testing; see [provider limitations](PROVIDERS.md).
- Explicit account linking: matching email alone never links a provider identity.
- Guarded `net/http` routes, the `auth.current_session` Kernel action, Transport route bindings, and an explicitly registered `nexssflow` bundle.
- Eight importable Flow routes in [`nexssflow/nflows/auth.nflow`](nexssflow/nflows/auth.nflow). Flow hosts supply per-request auth dependencies, trusted identity, and the HTTP request/response exchange; the raw `HTTPHandler` attaches its exchange automatically. See the [Flow integration guide](nexssflow/README.md).

## Host responsibilities

The host must supply account persistence and transaction guarantees; registration and email-verification policy; email templates and canonical links; session and cookie issuance; CSRF/origin checks; trusted request identity; rate-limit thresholds and trusted caller-key derivation (the package provides a reusable rate-limited `RequestBoundary` decorator); OAuth provider configuration and fixed callback URLs; and application authorization. The library does not grant tenant, workspace, project, or resource permissions. Hosts must authorize each such access from trusted server-side identity and policy. See [host integration](HOST_INTEGRATION.md).

For public browser-facing auth, use the Turnstile-protected constructor and configure a server-side verifier. `NewHTTPHandler` and the Flow bundle's lower-level boundary constructors remain available when the host intentionally supplies an equivalent anti-abuse check itself; omitting both is not a secure public deployment.

## Cloudflare Turnstile setup

Configure these values in the deployment's secret manager or host environment. The site key is public and belongs in the browser app; the secret key must remain server-side. This library does not load `.env` files or read environment variables automatically.

```text
TURNSTILE_SITE_KEY=<public Cloudflare site key>
TURNSTILE_SECRET_KEY=<server-only Cloudflare secret key>
TURNSTILE_EXPECTED_HOSTNAME=auth.example.com
```

Build the verifier and secure HTTP handler after the host has loaded its secrets:

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

The secure constructor requires action-bound responses for login, registration, password reset/forgot-password, email verification and resend, OAuth begin, and desktop authorization start. The browser must render the widget with the matching action (`login`, `register`, `password_reset`, `email_verify`, `oauth_begin`, or `desktop_start`) and send the response as `turnstile_token`; email resend uses the same `email_verify` action. OAuth callbacks, authenticated linking/logout, and PKCE code exchange are protected by their separate state/session controls. Siteverify outages fail closed with a retryable `503`; rejected or missing responses are denied.

For Flow, wrap the host `ActionBoundary` with `nexssflow.NewTurnstileActionBoundary` and `auth.DefaultTurnstileOperations()`; see [Flow Turnstile setup](nexssflow/README.md#turnstile-setup). Use Cloudflare's [server-side Siteverify API](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) and their [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) only in non-production tests. A successful test key is not evidence that production keys, hostnames, browser widgets, or application middleware are correctly configured.

## Legacy API

The old `auth.New(Config)` plugin is deprecated and now refuses to initialize unless `Config.Env` is explicitly `dev`, `development`, or `test`. Production hosts must use `NewService` with host-owned adapters. The legacy middleware no longer reads JWTs from query strings; use the `Authorization: Bearer` header where bearer credentials are appropriate.

## Install and verify

```sh
go get github.com/nexssp/auth@latest
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go mod tidy -diff
go mod verify
```

These checks validate code and fixtures, not a consuming application's database transactions, cookies, middleware, browser widget, or live identity-provider configuration. Facebook remains unverified against a live Meta app.
