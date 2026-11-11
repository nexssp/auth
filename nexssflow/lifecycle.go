package nexssflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/nexssp/auth"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
)

// ActionBoundary applies the host's caller, CSRF/origin, Turnstile, and
// rate-limit policy before a credential-bearing Flow action invokes auth.
// Hosts must derive those checks from trusted request context, never from
// caller-supplied identity fields.
type ActionBoundary interface {
	AuthorizeAuthFlowAction(ctx context.Context, operation auth.BoundaryOperation, turnstileToken string) error
}

type sensitiveInput string

func (sensitiveInput) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }
func (sensitiveInput) String() string               { return "[REDACTED]" }
func (sensitiveInput) GoString() string             { return "[REDACTED]" }
func (sensitiveInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (sensitiveInput) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type registerRequest struct {
	Email          sensitiveInput `json:"email"`
	Username       sensitiveInput `json:"username"`
	Password       sensitiveInput `json:"password"`
	Confirmation   sensitiveInput `json:"confirmation"`
	InviteCode     sensitiveInput `json:"invite_code"`
	TermsAccepted  bool           `json:"terms_accepted"`
	TurnstileToken sensitiveInput `json:"turnstile_token"`
}

type registerResponse struct {
	Registered        bool                       `json:"registered"`
	Authenticated     bool                       `json:"authenticated"`
	EmailVerification auth.EmailVerificationMode `json:"email_verification"`
	Message           string                     `json:"message,omitempty"`
}

type loginRequest struct {
	Identifier     sensitiveInput `json:"identifier"`
	Password       sensitiveInput `json:"password"`
	TurnstileToken sensitiveInput `json:"turnstile_token"`
}

type loginResponse struct {
	Authenticated  bool   `json:"authenticated"`
	CredentialType string `json:"credential_type"`
}

type logoutRequest struct{}

type logoutResponse struct {
	Authenticated bool `json:"authenticated"`
}

type passwordForgotRequest struct {
	Email          sensitiveInput `json:"email"`
	TurnstileToken sensitiveInput `json:"turnstile_token"`
}

type passwordForgotResponse struct {
	Message string `json:"message"`
}

type passwordResetRequest struct {
	Token        sensitiveInput `json:"token"`
	Password     sensitiveInput `json:"password"`
	Confirmation sensitiveInput `json:"confirmation"`
}

type passwordResetResponse struct {
	PasswordChanged bool `json:"password_changed"`
}

type emailVerifyRequest struct {
	Token          sensitiveInput `json:"token"`
	TurnstileToken sensitiveInput `json:"turnstile_token"`
}

type emailVerifyResponse struct {
	EmailVerified bool `json:"email_verified"`
}

type emailResendRequest struct {
	Email          sensitiveInput `json:"email"`
	TurnstileToken sensitiveInput `json:"turnstile_token"`
}

type emailResendResponse struct {
	Message string `json:"message"`
}

func newRegisterAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.register", "Register a password account using host-owned policy and a host-established browser session", boundary, auth.BoundaryRegister, func(request registerRequest) string {
		return string(request.TurnstileToken)
	}, false, func(ctx context.Context, request registerRequest) (registerResponse, error) {
		attempt := auth.RegistrationAttempt{
			Email:         string(request.Email),
			Username:      string(request.Username),
			InviteCode:    string(request.InviteCode),
			TermsAccepted: request.TermsAccepted,
		}
		account, err := service.RegisterPassword(ctx, attempt, string(request.Password), string(request.Confirmation))
		notificationFailed := err != nil && account.ID != ""
		if err != nil && !notificationFailed {
			return registerResponse{}, safeServiceError(err)
		}
		mode, err := service.EmailVerificationMode(ctx)
		if err != nil {
			return registerResponse{}, safeServiceError(err)
		}
		authenticated := mode != auth.VerificationRequired || account.EmailVerified
		if authenticated {
			if err := service.StartBrowserSession(ctx, account); err != nil {
				return registerResponse{}, safeServiceError(err)
			}
		}
		response := registerResponse{Registered: true, Authenticated: authenticated, EmailVerification: mode}
		if notificationFailed {
			response.Message = "Account created, but the verification email could not be sent. Request a new verification email if needed."
		}
		return response, nil
	})
}

func newLoginAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.login", "Authenticate with a password and establish a host-owned browser session", boundary, auth.BoundaryLogin, func(request loginRequest) string {
		return string(request.TurnstileToken)
	}, false, func(ctx context.Context, request loginRequest) (loginResponse, error) {
		account, err := service.AuthenticatePassword(ctx, string(request.Identifier), string(request.Password))
		if err != nil {
			return loginResponse{}, safeServiceError(err)
		}
		if err := service.StartBrowserSession(ctx, account); err != nil {
			return loginResponse{}, safeServiceError(err)
		}
		return loginResponse{Authenticated: true, CredentialType: "browser_session"}, nil
	})
}

func newLogoutAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.logout", "End the current host-owned browser session", boundary, auth.BoundaryLogout, func(logoutRequest) string { return "" }, false, func(ctx context.Context, _ logoutRequest) (logoutResponse, error) {
		if err := service.EndBrowserSession(ctx); err != nil {
			return logoutResponse{}, safeServiceError(err)
		}
		return logoutResponse{Authenticated: false}, nil
	})
}

func newPasswordForgotAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.password_forgot", "Request a password-reset email without revealing whether an account exists", boundary, auth.BoundaryPasswordReset, func(request passwordForgotRequest) string {
		return string(request.TurnstileToken)
	}, false, func(ctx context.Context, request passwordForgotRequest) (passwordForgotResponse, error) {
		if err := service.RequestPasswordReset(ctx, string(request.Email)); err != nil && isCancellation(err) {
			return passwordForgotResponse{}, safeServiceError(err)
		}
		return passwordForgotResponse{Message: "If an account matches that email, a reset link will be sent."}, nil
	})
}

func newPasswordResetAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.password_reset", "Consume a one-time password-reset token and revoke prior auth state", boundary, auth.BoundaryPasswordReset, func(passwordResetRequest) string { return "" }, false, func(ctx context.Context, request passwordResetRequest) (passwordResetResponse, error) {
		if err := service.ResetPassword(ctx, string(request.Token), string(request.Password), string(request.Confirmation)); err != nil {
			return passwordResetResponse{}, safeServiceError(err)
		}
		return passwordResetResponse{PasswordChanged: true}, nil
	})
}

func newEmailVerifyAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.email_verify", "Consume a one-time email-verification token", boundary, auth.BoundaryEmailVerify, func(request emailVerifyRequest) string {
		return string(request.TurnstileToken)
	}, false, func(ctx context.Context, request emailVerifyRequest) (emailVerifyResponse, error) {
		if err := service.VerifyEmail(ctx, string(request.Token)); err != nil {
			return emailVerifyResponse{}, safeServiceError(err)
		}
		return emailVerifyResponse{EmailVerified: true}, nil
	})
}

func newEmailResendAction(service *auth.Service, boundary ActionBoundary) action.AnyAction {
	return newLifecycleAction("auth.email_resend", "Request an email-verification message without revealing account state", boundary, auth.BoundaryEmailVerify, func(request emailResendRequest) string {
		return string(request.TurnstileToken)
	}, false, func(ctx context.Context, request emailResendRequest) (emailResendResponse, error) {
		if err := service.RequestEmailVerification(ctx, string(request.Email)); err != nil && isCancellation(err) {
			return emailResendResponse{}, safeServiceError(err)
		}
		return emailResendResponse{Message: "If verification is available for that address, an email will be sent."}, nil
	})
}

func newLifecycleAction[Request, Response any](name, description string, boundary ActionBoundary, operation auth.BoundaryOperation, turnstile func(Request) string, requiresAuth bool, execute func(context.Context, Request) (Response, error)) *action.BuiltAction[Request, Response] {
	builder := action.New(name, func(ctx context.Context, request Request) (Response, error) {
		var zero Response
		if err := boundary.AuthorizeAuthFlowAction(ctx, operation, turnstile(request)); err != nil {
			return zero, safeBoundaryError(err)
		}
		response, err := execute(ctx, request)
		if err != nil {
			return zero, err
		}
		return response, nil
	}).Description(description).Internal()
	if requiresAuth {
		builder.RequireAuth()
	}
	return builder.Build()
}

func safeBoundaryError(err error) error {
	if isCancellation(err) {
		return safeServiceError(err)
	}
	if errors.Is(err, auth.ErrRateLimited) {
		return xerr.TooManyRequests("Authentication request was not accepted")
	}
	return xerr.Forbidden("Authentication request was not accepted")
}

func safeServiceError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return xerr.Canceled("Authentication operation was canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return xerr.Timeout("Authentication operation timed out")
	case errors.Is(err, auth.ErrInvalidCredentials):
		return xerr.Unauthorized("Invalid credentials")
	case errors.Is(err, auth.ErrEmailNotVerified):
		return xerr.Forbidden("Email verification is required")
	case errors.Is(err, auth.ErrInvalidInput), errors.Is(err, auth.ErrInvalidOneTimeToken), errors.Is(err, auth.ErrInvalidDesktopAuth):
		return xerr.BadRequest("Invalid authentication input")
	case errors.Is(err, auth.ErrPasswordResetUnavailable), errors.Is(err, auth.ErrVerificationUnavailable), errors.Is(err, auth.ErrVerificationModeUnset):
		return xerr.Unavailable("Authentication operation is unavailable")
	default:
		return xerr.Internal("Authentication operation failed")
	}
}

func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

var _ json.Marshaler = sensitiveInput("")
var _ fmt.Stringer = sensitiveInput("")
var _ fmt.GoStringer = sensitiveInput("")
var _ fmt.Formatter = sensitiveInput("")
var _ slog.LogValuer = sensitiveInput("")
