// Package nexssflow exposes auth session and host-authorized lifecycle actions
// to Flow runners. The Bundle factory supports module @require; the host must
// still supply per-execution dependencies through WithRuntimeDependencies.
package nexssflow

import (
	"embed"
	"errors"

	"github.com/nexssp/auth"
	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/kernel/action"
)

const (
	BundleID         = "nexssp_auth_nexssflow"
	LibraryName      = "auth"
	AuthRoutesModule = "nflows/auth.nflow"
)

//go:embed nflows examples/*.nflow
var fixtures embed.FS

// Bundle is the conventional Flow extension factory resolved by
// `@require github.com/nexssp/auth`. Dependencies are read from each execution
// context, so this function never manufactures host policy, persistence, or
// security configuration.
func Bundle(_ map[string]string) compiler.Bundle {
	actions := []action.AnyAction{
		runtimeAction[auth.CurrentSessionRequest, auth.CurrentSessionResponse](
			"auth.current_session", "Read the current host-owned browser session",
			func(service *auth.Service, _ ActionBoundary) action.AnyAction {
				return auth.NewCurrentSessionAction(service)
			},
		),
		runtimeAction[registerRequest, registerResponse](
			"auth.register", "Register a password account using host-owned policy and a host-established browser session", newRegisterAction,
		),
		runtimeAction[loginRequest, loginResponse](
			"auth.login", "Authenticate with a password and establish a host-owned browser session", newLoginAction,
		),
		runtimeAction[logoutRequest, logoutResponse](
			"auth.logout", "End the current host-owned browser session", newLogoutAction,
		),
		runtimeAction[passwordForgotRequest, passwordForgotResponse](
			"auth.password_forgot", "Request a password-reset email without revealing whether an account exists", newPasswordForgotAction,
		),
		runtimeAction[passwordResetRequest, passwordResetResponse](
			"auth.password_reset", "Consume a one-time password-reset token and revoke prior auth state", newPasswordResetAction,
		),
		runtimeAction[emailVerifyRequest, emailVerifyResponse](
			"auth.email_verify", "Consume a one-time email-verification token", newEmailVerifyAction,
		),
		runtimeAction[emailResendRequest, emailResendResponse](
			"auth.email_resend", "Request an email-verification message without revealing account state", newEmailResendAction,
		),
	}
	return withAuthRoutesModule(compiler.Bundle{
		ID:        BundleID,
		Libraries: []action.Library{{Name: LibraryName, Actions: actions}},
		Fixtures:  fixtures,
	})
}

// NewBundle preserves the session-only bundle for hosts that have not configured
// Flow-action request authorization. Credential-bearing actions are not mounted.
func NewBundle(service *auth.Service) compiler.Bundle {
	return newBundle(service, nil)
}

// NewBundleWithBoundary exposes auth lifecycle actions only when the host
// provides their mandatory caller, CSRF/origin, Turnstile, and rate-limit guard.
func NewBundleWithBoundary(service *auth.Service, boundary ActionBoundary) (compiler.Bundle, error) {
	if service == nil || boundary == nil {
		return compiler.Bundle{}, errors.New("nexssflow: auth service and Flow action boundary are required")
	}
	return newBundle(service, boundary), nil
}

func newBundle(service *auth.Service, boundary ActionBoundary) compiler.Bundle {
	actions := []action.AnyAction{auth.NewCurrentSessionAction(service)}
	if boundary != nil {
		actions = append(actions,
			newRegisterAction(service, boundary),
			newLoginAction(service, boundary),
			newLogoutAction(service, boundary),
			newPasswordForgotAction(service, boundary),
			newPasswordResetAction(service, boundary),
			newEmailVerifyAction(service, boundary),
			newEmailResendAction(service, boundary),
		)
	}
	return compiler.Bundle{
		ID:        BundleID,
		Libraries: []action.Library{{Name: LibraryName, Actions: actions}},
		Fixtures:  fixtures,
	}
}

func withAuthRoutesModule(bundle compiler.Bundle) compiler.Bundle {
	bundle.SourceModules = fixtures
	bundle.ExportedModules = []string{AuthRoutesModule}
	return bundle
}
