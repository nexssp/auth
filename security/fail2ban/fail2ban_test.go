package fail2ban_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"

	"github.com/nexssp/auth/security/fail2ban"
)

func TestFail2Ban_MemoryProtector(t *testing.T) {
	t.Parallel()

	// 2 failures allowed within 100ms window, 200ms lockout duration
	protector := fail2ban.NewMemoryProtector(2, 100*time.Millisecond, 200*time.Millisecond)

	act := action.New("login.attempt", func(_ context.Context, req string) (string, error) {
		if req == "invalid" {
			return "", xerr.Unauthorized("bad password")
		}
		return "logged_in", nil
	}).
		Use(fail2ban.Fail2Ban[string, string](protector, func(_ context.Context, _ string) string {
			return "user-ip-127.0.0.1"
		})).
		Build()

	ctx := context.Background()

	// Failure 1
	_, err := act.Do(ctx, "invalid")
	if xerr.KindFrom(err) != xerr.KindUnauthorized {
		t.Fatalf("expected Unauthorized, got %v", err)
	}

	// Failure 2 -> Triggers penalty box
	_, err = act.Do(ctx, "invalid")
	if xerr.KindFrom(err) != xerr.KindUnauthorized {
		t.Fatalf("expected Unauthorized, got %v", err)
	}

	// Attempt 3 (Even with valid credentials) -> Must be blocked immediately with TooManyRequests
	_, err = act.Do(ctx, "valid_pass")
	if xerr.KindFrom(err) != xerr.KindTooManyRequests {
		t.Fatalf("expected TooManyRequests (banned IP), got %v", err)
	}

	// Wait for lockout window to expire
	time.Sleep(250 * time.Millisecond)

	// Attempt 4 -> Should pass now
	res, err := act.Do(ctx, "valid_pass")
	if err != nil || res != "logged_in" {
		t.Fatalf("expected login to succeed after lockout expiry, got err: %v", err)
	}
}
