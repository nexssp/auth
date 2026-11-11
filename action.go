package auth

import (
	"context"
	"errors"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/transport/thttp"
)

const currentSessionActionTimeout = 5 * time.Second

// CurrentSessionRequest contains no caller-supplied identity or credentials.
type CurrentSessionRequest struct{}

// CurrentSessionResponse contains only the public identity fields needed by a
// caller. Password hashes, bearer credentials, and auth-version state are never
// returned by this action.
type CurrentSessionResponse struct {
	AccountID     string `json:"account_id"`
	EmailVerified bool   `json:"email_verified"`
}

// NewCurrentSessionAction returns the read-only Kernel action surface for auth.
// It verifies both Kernel's trusted user scope and the host's current browser
// session; credential entry and exchange operations remain on HTTP routes.
func NewCurrentSessionAction(service *Service) *action.BuiltAction[CurrentSessionRequest, CurrentSessionResponse] {
	return action.New("auth.current_session", func(ctx context.Context, _ CurrentSessionRequest) (CurrentSessionResponse, error) {
		userID := xctx.UserIDFrom(ctx)
		if userID == "" {
			return CurrentSessionResponse{}, xerr.Unauthorized("Not authenticated")
		}
		if service == nil {
			return CurrentSessionResponse{}, xerr.Unavailable("Authentication service is not configured")
		}

		account, authenticated, err := service.CurrentBrowserAccount(ctx)
		if err != nil {
			return CurrentSessionResponse{}, currentSessionError(err)
		}
		if !authenticated || account.ID != userID {
			return CurrentSessionResponse{}, xerr.Unauthorized("Not authenticated")
		}
		return CurrentSessionResponse{AccountID: account.ID, EmailVerified: account.EmailVerified}, nil
	}).Description("Return the minimal identity for the current authenticated browser session").RequireAuth().Route(thttp.GET("/auth/session")).Resilient(action.ResilienceConfig{
		Timeout: currentSessionActionTimeout,
	}).Build()
}

func currentSessionError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return xerr.Canceled("Authentication session lookup was canceled", err)
	case errors.Is(err, context.DeadlineExceeded):
		return xerr.Timeout("Authentication session lookup timed out", err)
	default:
		return xerr.Internal("Could not load the current authentication session", err)
	}
}
