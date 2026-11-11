package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/transport/thttp"
)

func TestCurrentSessionActionRequiresMatchingTrustedSession(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	account := h.accounts.seedPassword(t, "action@example.test", "action-user", true)
	if err := h.service.StartBrowserSession(context.Background(), account); err != nil {
		t.Fatal(err)
	}

	act := NewCurrentSessionAction(h.service)
	meta := act.GetMeta()
	if meta.Name != "auth.current_session" || !meta.RequiresAuth || meta.Timeout != currentSessionActionTimeout {
		t.Fatalf("action metadata = %+v", meta)
	}
	bindings := act.GetBindings()
	if len(bindings) != 1 {
		t.Fatalf("bindings = %#v, want one GET route", bindings)
	}
	route, ok := bindings[0].(thttp.HTTPRoute)
	if !ok || route.Method != http.MethodGet || route.Path != "/auth/session" {
		t.Fatalf("route binding = %#v, want GET /auth/session", bindings[0])
	}

	ctx := xctx.WithUserID(context.Background(), account.ID)
	got, err := act.Do(ctx, CurrentSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != account.ID || !got.EmailVerified {
		t.Fatalf("response = %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{account.PasswordHash, account.Email, account.Username, "auth_version"} {
		if secret != "" && strings.Contains(string(encoded), secret) {
			t.Fatalf("response disclosed non-public account field %q: %s", secret, encoded)
		}
	}

	for _, userID := range []string{"", "different-account"} {
		_, err := act.Do(xctx.WithUserID(context.Background(), userID), CurrentSessionRequest{})
		if err == nil || xerr.From(err).Kind != xerr.KindUnauthorized {
			t.Errorf("user ID %q: error = %v, want unauthorized", userID, err)
		}
	}
}

func TestCurrentSessionActionClassifiesLookupTimeout(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	h.service.config.BrowserSessions = contextErrorSessions{}

	ctx, cancel := context.WithDeadline(xctx.WithUserID(context.Background(), "account-1"), time.Now().Add(-time.Second))
	defer cancel()
	_, err := NewCurrentSessionAction(h.service).Do(ctx, CurrentSessionRequest{})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || xerr.From(err).Kind != xerr.KindTimeout {
		t.Fatalf("error = %v, want timeout classification", err)
	}
}

type contextErrorSessions struct{}

func (contextErrorSessions) EstablishBrowserSession(context.Context, BrowserSession) error {
	return nil
}

func (contextErrorSessions) CurrentBrowserSession(ctx context.Context) (BrowserSession, bool, error) {
	return BrowserSession{}, false, ctx.Err()
}

func (contextErrorSessions) EndBrowserSession(context.Context) error {
	return nil
}
