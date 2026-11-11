package ratelimit_test

import (
	"context"
	"testing"

	"github.com/nexssp/auth/security/ratelimit"
)

func TestMemoryLimiter_Allow(t *testing.T) {
	t.Parallel()

	// 10 RPS with burst capacity of 2
	limiter := ratelimit.NewMemoryLimiter(10.0, 2)
	ctx := context.Background()

	key := "client-ip-10.0.0.1"

	// 1st request -> Allowed
	allowed, err := limiter.Allow(ctx, key)
	if err != nil || !allowed {
		t.Fatalf("first request should be allowed")
	}

	// 2nd request (Burst 2) -> Allowed
	allowed, err = limiter.Allow(ctx, key)
	if err != nil || !allowed {
		t.Fatalf("second request within burst should be allowed")
	}

	// 3rd rapid request -> Exceeds burst capacity -> Rejected
	allowed, err = limiter.Allow(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("third request should be rate-limited")
	}

	// Independent key should still have full burst available
	allowedOther, err := limiter.Allow(ctx, "client-ip-10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowedOther {
		t.Fatal("independent client key should be allowed")
	}
}
