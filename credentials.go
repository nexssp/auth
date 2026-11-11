package auth

import (
	"context"
	"time"
)

type browserSessionBindingContextKey struct{}

// WithBrowserSessionBinding attaches the SHA-256 digest of the current opaque
// browser-cookie ID to a request context. Durable OAuth stores use it to bind
// one-use state to the same browser session without storing the cookie value.
func WithBrowserSessionBinding(ctx context.Context, sessionIDDigest string) context.Context {
	return context.WithValue(ctx, browserSessionBindingContextKey{}, sessionIDDigest)
}

// BrowserSessionBinding returns the opaque-cookie digest attached by the host
// session middleware. Callers must never put the raw cookie value in context.
func BrowserSessionBinding(ctx context.Context) (string, bool) {
	digest, ok := ctx.Value(browserSessionBindingContextKey{}).(string)
	return digest, ok && digest != ""
}

// BrowserSession is the policy-neutral identity/time data a host may place in
// its browser-session mechanism. AuthVersion corresponds to a host's account
// session version; it is not an organization role or authorization policy.
type BrowserSession struct {
	Subject     string
	AuthVersion uint64
	StartedAt   time.Time
	ExpiresAt   time.Time
}

// BrowserSessionHost is the explicit seam for browser cookie/session behavior.
// The host owns cookie attributes, session-ID rotation, CSRF state, absolute
// expiry enforcement, database identity binding, and session invalidation.
// This is deliberately distinct from DesktopBearerStore; browser cookies are
// not desktop bearer credentials.
type BrowserSessionHost interface {
	EstablishBrowserSession(ctx context.Context, session BrowserSession) error
	CurrentBrowserSession(ctx context.Context) (BrowserSession, bool, error)
	EndBrowserSession(ctx context.Context) error
}

// DesktopBearer is the neutral server-side record for a desktop bearer token.
// Store the token digest, not the plaintext value.
type DesktopBearer struct {
	Subject     string
	AuthVersion uint64
	ExpiresAt   time.Time
}

// DesktopBearerStore is a distinct host seam for server-side opaque bearer
// records. Implementations own persistence, revocation, expiry comparisons, and
// any last-used bookkeeping; the module supplies token generation and digesting.
// Resolve must reject revoked, expired, or stale-AuthVersion credentials.
type DesktopBearerStore interface {
	StoreDesktopBearer(ctx context.Context, digest string, bearer DesktopBearer) error
	ResolveDesktopBearer(ctx context.Context, digest string, now time.Time) (DesktopBearer, bool, error)
	RevokeDesktopBearer(ctx context.Context, digest string, at time.Time) (bool, error)
}
