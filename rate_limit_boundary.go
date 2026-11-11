package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nexssp/auth/security/ratelimit"
)

// ErrRateLimiterUnavailable indicates that caller-key derivation or the limiter
// backend failed; callers must treat the request as unavailable, not as allowed.
var ErrRateLimiterUnavailable = errors.New("authentication rate limiter is unavailable")

// RateLimitKeyFunc derives a stable per-caller key from trusted host state.
// Hosts must not trust raw forwarded-IP headers; configure trusted-proxy handling
// before deriving an address. Return a keyed digest instead of raw personal data
// when the limiter backend would otherwise retain identifiers.
type RateLimitKeyFunc func(ctx context.Context, operation BoundaryOperation, request *http.Request) (string, error)

// RateLimitConfig composes a host request boundary with the package's shared
// limiter contract. Default applies to every auth operation; Operations may
// override individual operations to use different thresholds or backends. The
// adapter prefixes keys with the operation so buckets stay independent.
type RateLimitConfig struct {
	Default    ratelimit.Limiter
	Operations map[BoundaryOperation]ratelimit.Limiter
	Key        RateLimitKeyFunc
}

// RateLimitedRequestBoundary applies a rate limit before delegating to the host
// boundary. Limiter errors fail closed and are reported as service unavailable.
type RateLimitedRequestBoundary struct {
	next       RequestBoundary
	defaultRL  ratelimit.Limiter
	operations map[BoundaryOperation]ratelimit.Limiter
	key        RateLimitKeyFunc
}

// NewRateLimitedRequestBoundary wraps next with a shared rate limit and optional
// operation-specific overrides. The caller retains ownership of all supplied
// limiters and the trusted caller-key derivation policy.
func NewRateLimitedRequestBoundary(next RequestBoundary, config RateLimitConfig) (*RateLimitedRequestBoundary, error) {
	if next == nil || config.Default == nil || config.Key == nil {
		return nil, errors.New("auth: next boundary, default rate limiter, and trusted rate-limit key function are required")
	}
	operations := make(map[BoundaryOperation]ratelimit.Limiter, len(config.Operations))
	for operation, limiter := range config.Operations {
		if !validBoundaryOperation(operation) || limiter == nil {
			return nil, fmt.Errorf("auth: invalid rate-limit override for operation %q", operation)
		}
		operations[operation] = limiter
	}
	return &RateLimitedRequestBoundary{
		next:       next,
		defaultRL:  config.Default,
		operations: operations,
		key:        config.Key,
	}, nil
}

// AuthorizeAuthRequest rate-limits a caller before invoking the host's remaining
// anti-abuse, CSRF, origin, and registration-policy checks.
func (boundary *RateLimitedRequestBoundary) AuthorizeAuthRequest(ctx context.Context, operation BoundaryOperation, request *http.Request, turnstileToken string) error {
	if boundary == nil || boundary.next == nil || boundary.defaultRL == nil || boundary.key == nil {
		return ErrRateLimiterUnavailable
	}
	if ctx == nil || request == nil || !validBoundaryOperation(operation) {
		return ErrRequestDenied
	}
	key, err := boundary.key(ctx, operation, request)
	if err != nil {
		return fmt.Errorf("%w: derive caller key: %w", ErrRateLimiterUnavailable, err)
	}
	if strings.TrimSpace(key) == "" {
		return ErrRequestDenied
	}
	limiter := boundary.defaultRL
	if override, ok := boundary.operations[operation]; ok {
		limiter = override
	}
	allowed, err := limiter.Allow(ctx, "auth:"+string(operation)+":"+key)
	if err != nil {
		return fmt.Errorf("%w: check operation %q: %w", ErrRateLimiterUnavailable, operation, err)
	}
	if !allowed {
		return ErrRateLimited
	}
	return boundary.next.AuthorizeAuthRequest(ctx, operation, request, turnstileToken)
}

func validBoundaryOperation(operation BoundaryOperation) bool {
	switch operation {
	case BoundaryLogin, BoundaryRegister, BoundaryPasswordReset, BoundaryEmailVerify,
		BoundaryOAuthBegin, BoundaryOAuthCallback, BoundaryOAuthLink,
		BoundaryDesktopStart, BoundaryDesktopExchange, BoundaryLogout:
		return true
	default:
		return false
	}
}
