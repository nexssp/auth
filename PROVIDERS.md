# OAuth provider adapters

All provider credentials, exact callback URLs, account provisioning, and provider availability are configured by the host. Provider identity is keyed by the provider's stable subject; equal email addresses never auto-link accounts. Linking an existing account requires authentication to that account and explicit host-backed linking.

| Provider | Adapter behavior | Host integration notes |
|---|---|---|
| Google | OIDC discovery; validates signed ID token, issuer, audience, expiry, nonce, subject, and explicitly verified email. Uses state and S256 PKCE. | Configure client credentials and an exact HTTPS callback; test the real callback and account-store transaction. |
| GitHub | OAuth code exchange with S256 PKCE; uses GitHub's stable numeric user ID and requires a verified primary email. | Configure the fixed callback and required scopes; validate production API behavior and rate/error handling. |
| Apple | OIDC discovery; signs an ES256 client-secret JWT and validates signed ID-token claims and verified email. Callback method is `POST` with `form_post`. | Secure the signing key and configure the exact callback. The browser session cookie must accompany the cross-site POST (`SameSite=None; Secure`). |
| Facebook | Manual OIDC authorization-code flow with S256 PKCE, pinned issuer/JWKS, RS256 signature, audience, time, nonce, and authorized-party checks. It uses a GET token exchange without an app secret. | **Experimental:** Meta says the manually built OIDC/PKCE flow is still in testing. Meta's published discovery claims do not promise `email_verified`; an email is treated as verified only when a signed `email_verified: true` claim is actually present. Validate against a real app before production. A token exchange places the one-use code and PKCE verifier in a URL, so redact query strings in outbound-proxy and HTTP instrumentation logs. |

## Facebook source references

Meta's [OIDC code-flow guide](https://developers.facebook.com/documentation/facebook-login/guides/advanced/oidc-token) says the manually built PKCE flow is “still in testing,” recommends S256, requires a nonce, and states that the app secret may be omitted when the code verifier is sent. Meta's [manual login guide](https://developers.facebook.com/documentation/facebook-login/guides/advanced/manual-flow) documents the v27.0 login and token endpoints. The [OIDC discovery document](https://www.facebook.com/.well-known/openid-configuration) publishes the issuer, JWKS URI, and supported claims; its current published claim list does not include `email_verified`.

The Facebook adapter therefore does not infer email ownership from an email claim alone. An already-linked provider subject may authenticate without an email; a new account with an unverified email must be handled according to explicit host verification policy. Never weaken this rule or auto-link by email.

## Verification boundaries

Provider tests use local endpoints and signed fixtures. They validate protocol parsing and claim checks, not production provider-console settings, real callbacks, live email claims, browser-cookie behavior, or host transactions. Meta's OIDC flow has no live-app end-to-end validation in this release.
