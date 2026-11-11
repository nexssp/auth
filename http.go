package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/transport"
)

const (
	maxAuthRequestBytes = 16 << 10
	jsonErrorKey        = "error"
	authenticatedKey    = "authenticated"
	messageKey          = "message"
	httpProviderApple   = "apple"
)

var (
	ErrRequestDenied = errors.New("authentication request denied by host boundary")
	ErrRateLimited   = errors.New("authentication request rate limited by host boundary")
)

// BoundaryOperation names the public operation for the host's Turnstile,
// terms, CSRF, registration eligibility, and rate-limit adapter.
type BoundaryOperation string

const (
	BoundaryLogin           BoundaryOperation = "login"
	BoundaryRegister        BoundaryOperation = "register"
	BoundaryPasswordReset   BoundaryOperation = "password_reset"
	BoundaryEmailVerify     BoundaryOperation = "email_verify"
	BoundaryOAuthBegin      BoundaryOperation = "oauth_begin"
	BoundaryOAuthCallback   BoundaryOperation = "oauth_callback"
	BoundaryOAuthLink       BoundaryOperation = "oauth_link"
	BoundaryDesktopStart    BoundaryOperation = "desktop_start"
	BoundaryDesktopExchange BoundaryOperation = "desktop_exchange"
	BoundaryLogout          BoundaryOperation = "logout"
)

// RequestBoundary is mandatory for public routes. The host supplies anti-abuse,
// registration-policy, CSRF, and rate-limit checks here. The core deliberately
// does not accept or trust forwarded IP headers itself.
type RequestBoundary interface {
	AuthorizeAuthRequest(ctx context.Context, operation BoundaryOperation, request *http.Request, turnstileToken string) error
}

// OAuthCallbackOutcome gives the trusted host enough context to restore its
// existing login/editor redirect behavior. The callback must use configured
// host destinations, never a URL supplied by the browser.
type OAuthCallbackOutcome struct {
	Provider     string
	AccountID    string
	Registration RegistrationAttempt
	DesktopState string
	Err          error
}

type OAuthCallbackRedirector func(ctx context.Context, outcome OAuthCallbackOutcome) (string, error)

// HTTPConfig contains an auth service and the mandatory untrusted-boundary guard.
type HTTPConfig struct {
	Service                 *Service
	Boundary                RequestBoundary
	OAuthCallbackRedirector OAuthCallbackRedirector
}

type HTTPHandler struct {
	service                 *Service
	boundary                RequestBoundary
	oauthCallbackRedirector OAuthCallbackRedirector
	mux                     *http.ServeMux
}

// NewHTTPHandler refuses to expose auth routes without the host security
// boundary that preserves Turnstile, terms, CSRF, and rate limiting.
func NewHTTPHandler(config HTTPConfig) (*HTTPHandler, error) {
	if config.Service == nil || config.Boundary == nil {
		return nil, errors.New("auth: HTTP service and host request boundary are required")
	}
	handler := &HTTPHandler{service: config.Service, boundary: config.Boundary, oauthCallbackRedirector: config.OAuthCallbackRedirector, mux: http.NewServeMux()}
	handler.mux.HandleFunc("POST /auth/login", handler.login)
	handler.mux.HandleFunc("POST /auth/register", handler.register)
	handler.mux.HandleFunc("POST /auth/logout", handler.logout)
	handler.mux.HandleFunc("POST /auth/password/forgot", handler.forgotPassword)
	handler.mux.HandleFunc("POST /auth/password/reset", handler.resetPassword)
	handler.mux.HandleFunc("POST /auth/email/verify", handler.verifyEmail)
	handler.mux.HandleFunc("POST /auth/email/resend", handler.resendVerification)
	handler.mux.HandleFunc("POST /auth/oauth/{provider}/begin", handler.beginOAuth)
	handler.mux.HandleFunc("GET /auth/oauth/{provider}/callback", handler.oauthCallback)
	handler.mux.HandleFunc("POST /auth/oauth/{provider}/callback", handler.oauthCallback)
	handler.mux.HandleFunc("POST /auth/oauth/link", handler.linkOAuth)
	handler.mux.HandleFunc("POST /auth/desktop/start", handler.desktopStart)
	handler.mux.HandleFunc("POST /auth/desktop/exchange", handler.desktopExchange)
	return handler, nil
}

func (handler *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	handler.mux.ServeHTTP(w, r)
}

type loginRequest struct {
	Identifier     string `json:"identifier"`
	Password       string `json:"password"`
	DesktopState   string `json:"desktop_state"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryLogin, input.TurnstileToken) {
		return
	}
	account, err := handler.service.AuthenticatePassword(r.Context(), input.Identifier, input.Password)
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	if err := handler.service.StartBrowserSession(r.Context(), account); err != nil {
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "Could not start a secure browser session."})
		return
	}
	if input.DesktopState != "" {
		callback, err := handler.service.IssueDesktopAuthCode(r.Context(), input.DesktopState, account)
		if err != nil {
			handler.writeServiceError(w, err)
			return
		}
		http.Redirect(w, r, callback, http.StatusSeeOther)
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]any{authenticatedKey: true, "credential_type": "browser_session"})
}

type registerRequest struct {
	Email          string `json:"email"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Confirmation   string `json:"confirmation"`
	InviteCode     string `json:"invite_code"`
	TermsAccepted  bool   `json:"terms_accepted"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) register(w http.ResponseWriter, r *http.Request) {
	var input registerRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryRegister, input.TurnstileToken) {
		return
	}
	attempt := RegistrationAttempt{Email: input.Email, Username: input.Username, InviteCode: input.InviteCode, TermsAccepted: input.TermsAccepted}
	account, err := handler.service.RegisterPassword(r.Context(), attempt, input.Password, input.Confirmation)
	notificationFailed := err != nil && account.ID != ""
	if err != nil && !notificationFailed {
		handler.writeServiceError(w, err)
		return
	}
	mode, err := handler.service.verificationMode(r.Context())
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	status := http.StatusCreated
	if mode == VerificationRequired || mode == VerificationOptional {
		status = http.StatusAccepted
	}
	authenticated := mode != VerificationRequired || account.EmailVerified
	if authenticated {
		if err := handler.service.StartBrowserSession(r.Context(), account); err != nil {
			handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "The account was created, but a secure browser session could not be started."})
			return
		}
	}
	response := map[string]any{"registered": true, "authenticated": authenticated, "email_verification": mode}
	if notificationFailed {
		response["message"] = "Account created, but the verification email could not be sent. Request a new verification email if needed."
	}
	handler.writeJSON(w, status, response)
}

func (handler *HTTPHandler) logout(w http.ResponseWriter, r *http.Request) {
	if !handler.authorize(w, r, BoundaryLogout, "") {
		return
	}
	if err := handler.service.EndBrowserSession(r.Context()); err != nil {
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "Could not end the browser session."})
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]bool{authenticatedKey: false})
}

type emailRequest struct {
	Email          string `json:"email"`
	Token          string `json:"token"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var input emailRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryPasswordReset, input.TurnstileToken) {
		return
	}
	if err := handler.service.RequestPasswordReset(r.Context(), input.Email); err != nil {
		// Keep the account-existence oracle closed, including delivery failures.
		handler.writeJSON(w, http.StatusAccepted, map[string]string{messageKey: "If an account matches that email, a reset link will be sent."})
		return
	}
	handler.writeJSON(w, http.StatusAccepted, map[string]string{messageKey: "If an account matches that email, a reset link will be sent."})
}

type resetRequest struct {
	Token          string `json:"token"`
	Password       string `json:"password"`
	Confirmation   string `json:"confirmation"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var input resetRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryPasswordReset, input.TurnstileToken) {
		return
	}
	if err := handler.service.ResetPassword(r.Context(), input.Token, input.Password, input.Confirmation); err != nil {
		handler.writeServiceError(w, err)
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]bool{"password_changed": true})
}

func (handler *HTTPHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var input emailRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryEmailVerify, input.TurnstileToken) {
		return
	}
	if err := handler.service.VerifyEmail(r.Context(), input.Token); err != nil {
		handler.writeServiceError(w, err)
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]bool{"email_verified": true})
}

func (handler *HTTPHandler) resendVerification(w http.ResponseWriter, r *http.Request) {
	var input emailRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryEmailVerify, input.TurnstileToken) {
		return
	}
	if err := handler.service.RequestEmailVerification(r.Context(), input.Email); err != nil {
		handler.writeJSON(w, http.StatusAccepted, map[string]string{messageKey: "If verification is available for that address, an email will be sent."})
		return
	}
	handler.writeJSON(w, http.StatusAccepted, map[string]string{messageKey: "If verification is available for that address, an email will be sent."})
}

type oauthBeginRequest struct {
	RedirectURL    string `json:"redirect_url"`
	LinkCurrent    bool   `json:"link_current_account"`
	InviteCode     string `json:"invite_code"`
	TermsAccepted  bool   `json:"terms_accepted"`
	DesktopState   string `json:"desktop_state"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) beginOAuth(w http.ResponseWriter, r *http.Request) {
	var input oauthBeginRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryOAuthBegin, input.TurnstileToken) {
		return
	}
	provider := r.PathValue("provider")
	registration := RegistrationAttempt{InviteCode: input.InviteCode, TermsAccepted: input.TermsAccepted}
	authorizationURL, err := handler.service.BeginProviderLogin(r.Context(), provider, input.RedirectURL, input.LinkCurrent, registration, input.DesktopState)
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	if !validProviderAuthorizationURL(provider, authorizationURL) {
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "The provider authorization URL is invalid."})
		return
	}
	http.Redirect(w, r, authorizationURL, http.StatusSeeOther)
}

func (handler *HTTPHandler) oauthCallback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider, ok := handler.service.config.OAuthProviders[providerName]
	if !ok || r.Method != provider.CallbackMethod() {
		w.Header().Set("Allow", "GET, POST")
		handler.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{jsonErrorKey: "The provider callback method is not allowed."})
		return
	}
	var state, code string
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			handler.writeJSON(w, http.StatusBadRequest, map[string]string{jsonErrorKey: "Invalid provider callback."})
			return
		}
		state, code = r.Form.Get("state"), r.Form.Get("code")
	} else {
		state, code = r.URL.Query().Get("state"), r.URL.Query().Get("code")
	}
	if !handler.authorize(w, r, BoundaryOAuthCallback, "") {
		return
	}
	result, err := handler.service.CompleteProviderCallback(r.Context(), providerName, state, code)
	if err != nil {
		if handler.redirectOAuthCallback(w, r, OAuthCallbackOutcome{Provider: providerName, Registration: result.Registration, DesktopState: result.DesktopState, Err: err}) {
			return
		}
		handler.writeServiceError(w, err)
		return
	}
	if err := handler.service.StartBrowserSession(r.Context(), result.Account); err != nil {
		if handler.redirectOAuthCallback(w, r, OAuthCallbackOutcome{Provider: providerName, AccountID: result.Account.ID, Registration: result.Registration, DesktopState: result.DesktopState, Err: err}) {
			return
		}
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "Could not start a secure browser session."})
		return
	}
	if result.DesktopCallbackURL != "" {
		http.Redirect(w, r, result.DesktopCallbackURL, http.StatusSeeOther)
		return
	}
	if handler.redirectOAuthCallback(w, r, OAuthCallbackOutcome{Provider: providerName, AccountID: result.Account.ID, Registration: result.Registration}) {
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]any{authenticatedKey: true, "credential_type": "browser_session", "provider": providerName})
}

func (handler *HTTPHandler) redirectOAuthCallback(w http.ResponseWriter, r *http.Request, outcome OAuthCallbackOutcome) bool {
	if handler.oauthCallbackRedirector == nil {
		return false
	}
	target, err := handler.oauthCallbackRedirector(r.Context(), outcome)
	if err != nil {
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "Could not complete provider sign-in."})
		return true
	}
	if target == "" {
		return false
	}
	if !validHostCallbackRedirect(target) {
		handler.writeJSON(w, http.StatusInternalServerError, map[string]string{jsonErrorKey: "The configured provider return URL is invalid."})
		return true
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

func (handler *HTTPHandler) linkOAuth(w http.ResponseWriter, r *http.Request) {
	if !handler.authorize(w, r, BoundaryOAuthLink, "") {
		return
	}
	if err := handler.service.LinkPendingProviderIdentity(r.Context()); err != nil {
		handler.writeServiceError(w, err)
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]bool{"linked": true})
}

type desktopStartRequest struct {
	State          string `json:"state"`
	Challenge      string `json:"code_challenge"`
	RedirectURI    string `json:"redirect_uri"`
	TurnstileToken string `json:"turnstile_token"`
}

func (handler *HTTPHandler) desktopStart(w http.ResponseWriter, r *http.Request) {
	var input desktopStartRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryDesktopStart, input.TurnstileToken) {
		return
	}
	if err := handler.service.StartDesktopAuth(r.Context(), input.State, input.Challenge, input.RedirectURI); err != nil {
		handler.writeServiceError(w, err)
		return
	}
	handler.writeJSON(w, http.StatusCreated, map[string]bool{"started": true})
}

type desktopExchangeRequest struct {
	Code     string `json:"code"`
	Verifier string `json:"code_verifier"`
}

func (handler *HTTPHandler) desktopExchange(w http.ResponseWriter, r *http.Request) {
	var input desktopExchangeRequest
	if !handler.decodeJSON(w, r, &input) {
		return
	}
	if !handler.authorize(w, r, BoundaryDesktopExchange, "") {
		return
	}
	token, expires, err := handler.service.ExchangeDesktopAuthCode(r.Context(), input.Code, input.Verifier)
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	handler.writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_at": expires.UTC().Format(time.RFC3339)})
}

func (handler *HTTPHandler) authorize(w http.ResponseWriter, r *http.Request, operation BoundaryOperation, turnstileToken string) bool {
	if err := handler.boundary.AuthorizeAuthRequest(r.Context(), operation, r, turnstileToken); err != nil {
		status := http.StatusForbidden
		if errors.Is(err, ErrRateLimited) {
			status = http.StatusTooManyRequests
		} else if errors.Is(err, ErrTurnstileUnavailable) {
			status = http.StatusServiceUnavailable
		}
		handler.writeJSON(w, status, map[string]string{jsonErrorKey: "Authentication request was not accepted."})
		return false
	}
	return true
}

func (handler *HTTPHandler) decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("Content-Type") == "" || !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/json") {
		handler.writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{jsonErrorKey: "Send a JSON request."})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		handler.writeJSON(w, http.StatusBadRequest, map[string]string{jsonErrorKey: "Invalid authentication request."})
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		handler.writeJSON(w, http.StatusBadRequest, map[string]string{jsonErrorKey: "Invalid authentication request."})
		return false
	}
	return true
}

func (handler *HTTPHandler) writeServiceError(w http.ResponseWriter, err error) {
	var appErr *xerr.AppError
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		appErr = xerr.Unauthorized("Invalid email or password.", err)
	case errors.Is(err, ErrEmailNotVerified):
		appErr = xerr.Forbidden("Verify your email before signing in.", err)
	case errors.Is(err, ErrAccountLinkRequired):
		appErr = xerr.Conflict("Sign in to the existing account, then link this provider.", err)
	case errors.Is(err, ErrInvalidDesktopAuth), errors.Is(err, ErrInvalidOneTimeToken), errors.Is(err, ErrInvalidOAuthResponse):
		appErr = xerr.BadRequest("The authentication link or response is invalid or expired.", err)
	case errors.Is(err, ErrOAuthEmailMismatch):
		appErr = xerr.Conflict("The provider-verified email does not match the signed-in account.", err)
	case errors.Is(err, ErrVerificationUnavailable), errors.Is(err, ErrPasswordResetUnavailable), errors.Is(err, ErrOAuthUnavailable):
		appErr = xerr.Unavailable("This authentication method is not configured.", err)
	case errors.Is(err, ErrInvalidInput):
		appErr = xerr.BadRequest("Check the authentication details and try again.", err)
	default:
		appErr = xerr.Internal("Authentication service is temporarily unavailable.", err)
	}
	handler.writeJSON(w, transport.MapToHTTPStatus(appErr.Kind), map[string]string{jsonErrorKey: appErr.Message})
}

func (handler *HTTPHandler) writeJSON(w http.ResponseWriter, status int, value any) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		http.Error(w, `{"error":"Authentication service is temporarily unavailable."}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))); err != nil {
		return
	}
}

func validHostCallbackRedirect(value string) bool {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Opaque != "" {
		return false
	}
	if !parsed.IsAbs() {
		return parsed.Host == "" && strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//")
	}
	if parsed.Hostname() == "" {
		return false
	}
	scheme, host := strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname())
	return scheme == "https" || (scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"))
}

func validProviderAuthorizationURL(provider, value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	path := parsed.Path
	switch provider {
	case "google":
		return host == "accounts.google.com" && path == "/o/oauth2/v2/auth"
	case providerGitHub:
		return host == "github.com" && path == "/login/oauth/authorize"
	case providerFacebook:
		return host == "www.facebook.com" && path == "/v27.0/dialog/oauth"
	case httpProviderApple:
		return host == "appleid.apple.com" && path == "/auth/authorize"
	default:
		return false
	}
}
