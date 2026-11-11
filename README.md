# nexssp/auth

`github.com/nexssp/auth` is a reusable Go authentication module for Nexss ecosystem applications.

The module contains storage-neutral authentication use cases, provider adapters, guarded HTTP routes, a credential-free Kernel session action, and an opt-in Flow bundle. Applications supply account storage, registration policy, email delivery, browser-session and CSRF behavior, rate limiting, and deployment configuration.

## Included

- Password registration, login, password reset, and optional email verification. Bcrypt-compatible hashes include verification support for existing `$2y$` and `$2a$` hashes; the configured password policy is 12–72 bytes.
- Digest-only, one-use reset and verification tokens, with atomic consume-and-apply contracts delegated to host stores.
- Browser sessions through a host interface, kept separate from native desktop PKCE handoff codes and opaque bearer credentials.
- Google, GitHub, Apple, and Facebook provider adapters. Facebook uses Meta's manually built OIDC/PKCE flow, which Meta labels as testing; see [provider limitations](PROVIDERS.md).
- Explicit account linking: matching email alone never links a provider identity.
- A guarded `net/http` API, the `auth.current_session` Kernel action, Transport route bindings, and an explicitly registered `nexssflow` bundle.
- The Flow bundle exports [`nexssflow/nflows/auth.nflow`](nexssflow/nflows/auth.nflow) with eight route-bound pipelines. Use Transport's standard `thttp.listen`; the host supplies per-request auth dependencies, trusted identity, and the HTTP request/response exchange. OAuth and desktop endpoints remain available through `auth.NewHTTPHandler` on the host mux or as Transport raw handlers. See the [Flow integration guide](nexssflow/README.md).

## Host responsibilities

This module is not a complete login server or user database. The host must implement account persistence and transaction guarantees, registration and email-verification policy, email templates and canonical links, session and cookie issuance, CSRF/origin checks, trusted request identity, rate limits, optional Turnstile, OAuth provider configuration and registered callback URLs, and app authorization. See [host integration](HOST_INTEGRATION.md).

The Flow bundle does not load a `.env` file or define standard environment-variable names for these host-owned settings. Load database, session, mail, OAuth, and optional Turnstile secrets in the host process before starting Flow. Keep the Turnstile secret server-side and perform response-token verification in the host boundary; see [Flow environment and provider setup](nexssflow/README.md#environment-providers-and-turnstile).

Never trust a callback URL from browser input. Use fixed provider callback URLs. For Apple `form_post`, the host's session cookie must work on a cross-site POST (`SameSite=None; Secure`). Ensure OAuth callback and provider token-exchange URLs are redacted from proxy and application logs.

## Install

```sh
go get github.com/nexssp/auth@latest
```

## Verify

From the module root, using Go's default workspace resolution:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go mod tidy -diff
go mod verify
```

These checks validate local code and fixtures, not live identity-provider configuration or a consuming application's cookies, database transactions, middleware, or UI. Facebook remains unverified against a live Meta app.
