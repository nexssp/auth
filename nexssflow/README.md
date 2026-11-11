# `nexssflow`: importable authentication routes

The auth bundle exports [`nflows/auth.nflow`](nflows/auth.nflow), which defines eight route-bound pipelines. It does not create or start an HTTP server. Import the routes and use Transport's standard `thttp.listen`:

```nflow
@require github.com/nexssp/transport/thttp/nexssflow as thttp {
  addr: "127.0.0.1:8080"
}
@require github.com/nexssp/auth as auth
@include auth:nflows/auth.nflow AS auth_api
thttp.listen
```

The routes are `GET /auth/session` and `POST` for `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/password/forgot`, `/auth/password/reset`, `/auth/email/verify`, and `/auth/email/resend`. Transport discovers the route bindings; there is no `auth.listen` action or auth-specific server adapter.

## What the host supplies

The host still creates the `auth.Service`, its stores and policy adapters, and the Flow `ActionBoundary`. Each HTTP request must receive its own runtime dependencies through Transport's middleware hook. In that middleware, the host should:

1. validate the browser session and derive identity only from trusted host state;
2. attach the service and action boundary with `nexssflow.WithRuntimeDependencies`;
3. attach the active request and actual response writer with `auth.WithHTTPExchange`;
4. pass the resulting context to the next handler.

The Transport listener can be configured from the Go host with `thttpflow.WithRuntimeConfig`:

```go
flowCtx := thttpflow.WithRuntimeConfig(context.Background(), thttpflow.RuntimeConfig{
    Addr: "127.0.0.1:8080",
    Middlewares: []func(http.Handler) http.Handler{
        hostAuthRequestMiddleware(service, actionBoundary),
    },
})
_, err := runner.Execute(flowCtx, config, serverSource, "server.nflow", nil)
return err
```

`hostAuthRequestMiddleware` is application code, not an auth policy supplied by this package. It must set trusted user context only after validating the session cookie; never trust caller-provided identity headers. The host `ActionBoundary` protects the Flow credential operations with its origin/CSRF, rate-limit, registration, and anti-abuse policies. See [host integration](../HOST_INTEGRATION.md) for the complete host responsibilities.

`auth.WithHTTPExchange` is the bridge for a `BrowserSessionHost` that needs the live request or must set/clear a cookie on the response. A session host can call `auth.HTTPExchangeFromContext(ctx)` during `EstablishBrowserSession` or `EndBrowserSession`. Use it only for that request; do not retain or serialize the response writer. Cookie rotation, expiry, `Secure`, `HttpOnly`, `SameSite`, path/domain, and CSRF-token behavior remain host-owned.

## Turnstile setup

For a public browser-facing deployment, configure Cloudflare Turnstile in the host and wrap the host `ActionBoundary`; the Flow package does not load a `.env` file or read environment variables. Set `TURNSTILE_SITE_KEY` in the browser application, keep `TURNSTILE_SECRET_KEY` server-only, and configure `TURNSTILE_EXPECTED_HOSTNAME` to the exact hostname on which the widget is served. Load the secret from the deployment's secret manager before starting the process.

```go
verifier, err := auth.NewCloudflareTurnstileVerifier(auth.CloudflareTurnstileConfig{
    SecretKey:        os.Getenv("TURNSTILE_SECRET_KEY"),
    ExpectedHostname: os.Getenv("TURNSTILE_EXPECTED_HOSTNAME"),
})
if err != nil {
    return err
}

secureBoundary, err := nexssflow.NewTurnstileActionBoundary(
    hostActionBoundary,
    verifier,
    auth.DefaultTurnstileOperations()...,
)
if err != nil {
    return err
}

requestContext, err := nexssflow.WithRuntimeDependencies(requestContext, service, secureBoundary)
if err != nil {
    return err
}
```

Render the browser widget with the public site key and the action matching the operation, then send its response in the JSON `turnstile_token` field. The defaults require actions `login`, `register`, `password_reset` (for both forgot and reset), `email_verify` (also used by email resend), `oauth_begin`, and `desktop_start`. The server checks the Siteverify `success`, `hostname`, and exact `action` values; missing or rejected tokens are denied, and Siteverify outages fail closed. Do not verify the same token again in the wrapped host boundary.

For raw HTTP endpoints, use `auth.NewSecureHTTPHandler` with the same verifier. Use `auth.NewHTTPHandler` or custom Flow operations only when the host intentionally supplies equivalent anti-abuse verification itself. See Cloudflare's [Siteverify API](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) and [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/); test keys are for non-production tests only and do not validate the real site's configuration.

## OAuth and desktop endpoints

OAuth and desktop flows keep using the guarded core handler from `auth.NewSecureHTTPHandler`; the auth Flow module does not add fake pipelines for these raw HTTP protocols. To put them on the same Transport listener, register the handler's routes as `thttp.RawHandler` bindings in a host-owned action bundle. Transport v0.12.0 discovers raw-handler bindings alongside the Flow `:route` pipelines, and the same host middleware supplies the request context and response writer. Alternatively, mount the secure handler on a host-owned mux. The host `RequestBoundary` remains mandatory.

The raw endpoints are:

- `POST /auth/oauth/{provider}/begin`
- `GET` and `POST` `/auth/oauth/{provider}/callback`
- `POST /auth/oauth/link`
- `POST /auth/desktop/start`
- `POST /auth/desktop/exchange`

Register only paths not already served by Flow routes. If the host mux is used, avoid mounting duplicate patterns for `/auth/login`, `/auth/register`, and the other Flow routes.

## Flow use without an HTTP server

For action-level composition without a public HTTP listener, use [`examples/auth_full_lifecycle.nflow`](examples/auth_full_lifecycle.nflow) and attach `WithRuntimeDependencies(ctx, service, actionBoundary)` to each protected Flow execution. It does not start HTTP.

`NewBundleWithBoundary(service, boundary)` remains available for a statically configured bundle. `NewBundle(service)` remains session-only; credential-bearing actions are not mounted without their required host boundary.

## Request limits and credentials

The removed auth listener had an auth-specific 16 KiB request-body ceiling and required JSON for credential-bearing routes. Standard Transport applies its own general HTTP decoding and body limits instead. If the application requires a smaller ceiling or JSON-only requests, add that policy in host middleware; it is not imposed by the auth route module.

Never put passwords, tokens, Turnstile responses, or provider credentials in `.nflow` source, shell arguments, journals, retries, caches, or unredacted telemetry. Pass credential payloads through the host's protected runtime-input path. Keep provider callback URLs fixed and OAuth redirects allowlisted.
