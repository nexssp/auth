package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	PasswordMinBytes      = 12
	PasswordMaxBytes      = 72
	PasswordResetTTL      = time.Hour
	EmailVerificationTTL  = 24 * time.Hour
	OAuthStateTTL         = 10 * time.Minute
	DesktopAuthRequestTTL = 10 * time.Minute
	DesktopAuthCodeTTL    = 2 * time.Minute
	DesktopBearerTTL      = 30 * 24 * time.Hour
)

var (
	ErrAccountNotFound          = errors.New("account not found")
	ErrInvalidCredentials       = errors.New("invalid email or password")
	ErrEmailNotVerified         = errors.New("email verification is required")
	ErrInvalidInput             = errors.New("invalid authentication input")
	ErrVerificationUnavailable  = errors.New("email verification is unavailable")
	ErrPasswordResetUnavailable = errors.New("password reset is unavailable")
	ErrOAuthUnavailable         = errors.New("OAuth provider is unavailable")
	ErrAccountLinkRequired      = errors.New("sign in to the existing account to link this provider")
	ErrInvalidDesktopAuth       = errors.New("invalid or expired desktop authorization")
	ErrVerificationModeUnset    = errors.New("host email verification mode must be explicitly configured")
)

// EmailVerificationMode is a host-selected policy. There is intentionally no
// default. Each host must explicitly choose its deployment behavior.
type EmailVerificationMode string

const (
	VerificationDisabled EmailVerificationMode = "disabled"
	VerificationOptional EmailVerificationMode = "optional"
	VerificationRequired EmailVerificationMode = "required"
)

func (mode EmailVerificationMode) valid() bool {
	return mode == VerificationDisabled || mode == VerificationOptional || mode == VerificationRequired
}

// Account contains only generic authentication state. Organization membership,
// roles, platform-admin status, and invitation state remain application-owned.
type Account struct {
	ID            string
	Email         string
	Username      string
	PasswordHash  string
	EmailVerified bool
	AuthVersion   uint64
}

// NewPasswordAccount is passed to the host persistence adapter. PasswordHash is
// a bcrypt-compatible hash; the host owns uniqueness and bootstrap transactions.
type NewPasswordAccount struct {
	Email         string
	Username      string
	PasswordHash  string
	EmailVerified bool
}

// AccountStore is the application persistence seam. UpdatePasswordAndRevokeAuth
// must atomically update the password, increment its session version, revoke
// desktop credentials, and invalidate outstanding desktop exchanges/reset links.
type AccountStore interface {
	FindByIdentifier(ctx context.Context, identifier string) (Account, error)
	FindByEmail(ctx context.Context, email string) (Account, error)
	FindByID(ctx context.Context, id string) (Account, error)
	UpdatePasswordAndRevokeAuth(ctx context.Context, subject, passwordHash string) error
	MarkEmailVerified(ctx context.Context, subject string) error
	FindByProviderIdentity(ctx context.Context, provider, subject string) (Account, error)
	LinkProviderIdentity(ctx context.Context, userID, provider, subject, emailAtLink string) error
}

// RegistrationAttempt carries user input and optional host-defined registration
// context. The core passes invite and terms fields through without applying policy.
type RegistrationAttempt struct {
	Email         string
	Username      string
	InviteCode    string
	TermsAccepted bool
}

// HostPolicy owns registration decisions, the explicit verification mode, and
// provider-backed account creation. CreatePasswordAccount must perform all
// eligibility/invite/first-admin/terms checks and persist the account in one
// host transaction. ProvisionProviderAccount must apply those same rules and
// create the account plus linked identity atomically. It must not mark an
// unverified provider email verified unless the host independently verified it.
type HostPolicy interface {
	EmailVerificationMode(ctx context.Context) (EmailVerificationMode, error)
	CreatePasswordAccount(ctx context.Context, attempt RegistrationAttempt, account NewPasswordAccount) (Account, error)
	ProvisionProviderAccount(ctx context.Context, identity ProviderIdentity, attempt RegistrationAttempt) (Account, error)
}

// AuthEmail is a notification event, not a rendered message. The host owns its
// email templates, canonical links, sender identity, and delivery provider.
//
//nolint:revive // AuthEmail is the established exported package name and changing it breaks host integrations.
type AuthEmail struct {
	Kind      string
	To        string
	Token     string
	ExpiresAt time.Time
}

const (
	EmailPasswordReset = "password_reset"
	EmailVerifyAddress = "email_verification"
)

// EmailSender is implemented by the host's mailer/template adapter.
type EmailSender interface {
	SendAuthEmail(ctx context.Context, message AuthEmail) error
}

// OAuthStateStore persists a digest-keyed, short-lived login attempt. Consume
// must atomically remove one unexpired record before returning it.
type OAuthStateStore interface {
	SaveOAuthState(ctx context.Context, stateDigest string, state PendingOAuthState) error
	ConsumeOAuthState(ctx context.Context, stateDigest string, now time.Time) (PendingOAuthState, bool, error)
}

// PendingOAuthState stores PKCE/nonce secrets server-side; never send these
// values back to the browser except the derived authorization URL.
type PendingOAuthState struct {
	Provider     string
	Nonce        string
	Verifier     string
	RedirectURL  string
	LinkSubject  string
	Registration RegistrationAttempt
	DesktopState string
	StartedAt    time.Time
	ExpiresAt    time.Time
}

// PendingOAuthLinkStore is normally bound to the browser session. A pending
// identity is linked only after the user authenticates to the matching local
// account and explicitly invokes the link route. Its consume callback must only
// remove the intent when apply succeeds.
type PendingOAuthLinkStore interface {
	SavePendingOAuthLink(ctx context.Context, identity ProviderIdentity, expiresAt time.Time) error
	ConsumePendingOAuthLink(ctx context.Context, now time.Time, apply func(context.Context, ProviderIdentity) error) error
}

// DesktopAuthRequest and DesktopAuthCode are short-lived records required for
// the PHP-compatible browser-to-native PKCE handoff.
type DesktopAuthRequest struct {
	CodeChallenge string
	RedirectURI   string
	ExpiresAt     time.Time
}

type DesktopAuthCode struct {
	Subject       string
	AuthVersion   uint64
	CodeChallenge string
	ExpiresAt     time.Time
}

// DesktopAuthStore must implement atomic consume-and-apply operations. In
// particular, consuming a code and storing the bearer credential must share a
// transaction when the host database supports transactions.
type DesktopAuthStore interface {
	CreateDesktopAuthRequest(ctx context.Context, stateDigest string, request DesktopAuthRequest) error
	HasDesktopAuthRequest(ctx context.Context, stateDigest string, now time.Time) (bool, error)
	ConsumeDesktopAuthRequest(ctx context.Context, stateDigest string, now time.Time, apply func(context.Context, DesktopAuthRequest) error) error
	CreateDesktopAuthCode(ctx context.Context, codeDigest string, code DesktopAuthCode) error
	ConsumeDesktopAuthCode(ctx context.Context, codeDigest string, now time.Time, apply func(context.Context, DesktopAuthCode) error) error
}

// BrowserSessionLifetime lets the host preserve per-account session settings.
type BrowserSessionLifetime func(ctx context.Context, account Account) (time.Duration, error)

// ServiceConfig composes generic authentication with host-owned adapters. No
// email-verification mode is supplied here; HostPolicy must explicitly return
// disabled, optional, or required for each signup/login decision.
type ServiceConfig struct {
	Accounts               AccountStore
	Policy                 HostPolicy
	BrowserSessions        BrowserSessionHost
	BrowserSessionLifetime BrowserSessionLifetime
	Emails                 EmailSender
	PasswordResetTokens    OneTimeTokens
	EmailVerifyTokens      OneTimeTokens
	OAuthStates            OAuthStateStore
	PendingOAuthLinks      PendingOAuthLinkStore
	OAuthProviders         map[string]OAuthProvider
	DesktopAuth            DesktopAuthStore
	DesktopBearers         DesktopBearerStore
	DesktopBearerLifetime  time.Duration
	Now                    func() time.Time
}

// Service implements storage-neutral auth use cases. It contains no application
// database, invitation lifecycle, organization roles, Turnstile, rate limits, or
// email templates.
type Service struct {
	config ServiceConfig
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Accounts == nil || config.Policy == nil || config.BrowserSessions == nil || config.BrowserSessionLifetime == nil {
		return nil, errors.New("auth: account store, host policy, browser sessions, and browser lifetime are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.DesktopBearerLifetime == 0 {
		config.DesktopBearerLifetime = DesktopBearerTTL
	}
	if config.DesktopBearerLifetime < time.Minute {
		return nil, errors.New("auth: desktop bearer lifetime must be at least one minute")
	}
	providers := make(map[string]OAuthProvider, len(config.OAuthProviders))
	for name, provider := range config.OAuthProviders {
		if !supportedOAuthProvider(name) || provider == nil || provider.Name() != name {
			return nil, fmt.Errorf("auth: unsupported or mismatched OAuth provider %q", name)
		}
		providers[name] = provider
	}
	config.OAuthProviders = providers
	return &Service{config: config}, nil
}

func supportedOAuthProvider(name string) bool {
	return name == "google" || name == "github" || name == "facebook" || name == providerApple
}

func (s *Service) verificationMode(ctx context.Context) (EmailVerificationMode, error) {
	mode, err := s.config.Policy.EmailVerificationMode(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: read host email-verification mode: %w", err)
	}
	if !mode.valid() {
		return "", ErrVerificationModeUnset
	}
	return mode, nil
}

// EmailVerificationMode returns the host-selected mode for the current request.
// It deliberately has no package default; callers must keep host policy as the
// source of truth.
func (s *Service) EmailVerificationMode(ctx context.Context) (EmailVerificationMode, error) {
	return s.verificationMode(ctx)
}

// RegisterPassword creates a password account only after the host's eligibility
// policy permits it. disabled preserves immediate signup; optional and required
// send a verification event, with required enforced at login.
func (s *Service) RegisterPassword(ctx context.Context, attempt RegistrationAttempt, password, confirmation string) (Account, error) {
	attempt.Email = normalizeEmail(attempt.Email)
	if attempt.Email == "" || !validUsername(attempt.Username) || len(password) < PasswordMinBytes || len(password) > PasswordMaxBytes || password != confirmation {
		return Account{}, ErrInvalidInput
	}
	mode, err := s.verificationMode(ctx)
	if err != nil {
		return Account{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Account{}, fmt.Errorf("auth: hash password: %w", err)
	}
	account, err := s.config.Policy.CreatePasswordAccount(ctx, attempt, NewPasswordAccount{
		Email: attempt.Email, Username: attempt.Username, PasswordHash: hash,
		EmailVerified: mode == VerificationDisabled,
	})
	if err != nil {
		return Account{}, fmt.Errorf("auth: host password registration: %w", err)
	}
	if mode != VerificationDisabled {
		if err := s.sendVerification(ctx, account); err != nil {
			return account, err
		}
	}
	return account, nil
}

// AuthenticatePassword verifies local credentials, including legacy username
// lookup delegated to the host. It does not create a browser session or desktop
// token; callers choose the credential type explicitly.
func (s *Service) AuthenticatePassword(ctx context.Context, identifier, password string) (Account, error) {
	if identifier == "" || password == "" || len(password) > PasswordMaxBytes {
		return Account{}, ErrInvalidCredentials
	}
	account, err := s.config.Accounts.FindByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return Account{}, ErrInvalidCredentials
		}
		return Account{}, fmt.Errorf("auth: find account: %w", err)
	}
	verifyErr := VerifyPassword(password, account.PasswordHash)
	if verifyErr != nil {
		if errors.Is(verifyErr, ErrPasswordMismatch) || errors.Is(verifyErr, ErrUnsupportedPasswordHash) || errors.Is(verifyErr, ErrInvalidPasswordHash) {
			return Account{}, ErrInvalidCredentials
		}
		return Account{}, fmt.Errorf("auth: verify password: %w", verifyErr)
	}
	mode, err := s.verificationMode(ctx)
	if err != nil {
		return Account{}, err
	}
	if mode == VerificationRequired && !account.EmailVerified {
		return Account{}, ErrEmailNotVerified
	}
	return account, nil
}

// StartBrowserSession delegates cookie policy, session-ID rotation, CSRF,
// absolute expiry enforcement, and identity binding to the host.
func (s *Service) StartBrowserSession(ctx context.Context, account Account) error {
	if account.ID == "" {
		return ErrInvalidInput
	}
	duration, err := s.config.BrowserSessionLifetime(ctx, account)
	if err != nil {
		return fmt.Errorf("auth: choose browser-session lifetime: %w", err)
	}
	if duration <= 0 {
		return errors.New("auth: browser-session lifetime must be positive")
	}
	started := s.config.Now()
	return s.config.BrowserSessions.EstablishBrowserSession(ctx, BrowserSession{
		Subject: account.ID, AuthVersion: account.AuthVersion,
		StartedAt: started, ExpiresAt: started.Add(duration),
	})
}

func (s *Service) EndBrowserSession(ctx context.Context) error {
	return s.config.BrowserSessions.EndBrowserSession(ctx)
}

// CurrentBrowserAccount resolves the current host session and rejects expired
// or stale-version sessions; the host still owns cookie/CSRF handling.
func (s *Service) CurrentBrowserAccount(ctx context.Context) (Account, bool, error) {
	session, ok, err := s.config.BrowserSessions.CurrentBrowserSession(ctx)
	if err != nil || !ok {
		return Account{}, false, err
	}
	if session.Subject == "" || !session.ExpiresAt.After(s.config.Now()) {
		return Account{}, false, nil
	}
	account, err := s.config.Accounts.FindByID(ctx, session.Subject)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return Account{}, false, nil
		}
		return Account{}, false, fmt.Errorf("auth: load browser-session account: %w", err)
	}
	if account.AuthVersion != session.AuthVersion {
		return Account{}, false, nil
	}
	return account, true, nil
}

// RequestPasswordReset always has the same result for known and unknown email
// addresses. The host performs per-IP/per-email throttling at the HTTP boundary.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	if s.config.PasswordResetTokens.Store == nil || s.config.Emails == nil {
		return ErrPasswordResetUnavailable
	}
	email = normalizeEmail(email)
	if email == "" {
		return nil
	}
	account, err := s.config.Accounts.FindByEmail(ctx, email)
	if errors.Is(err, ErrAccountNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auth: find reset account: %w", err)
	}
	expires := s.config.Now().Add(PasswordResetTTL)
	token, err := s.config.PasswordResetTokens.Issue(ctx, account.ID, expires)
	if err != nil {
		return err
	}
	if err := s.config.Emails.SendAuthEmail(ctx, AuthEmail{Kind: EmailPasswordReset, To: account.Email, Token: token, ExpiresAt: expires}); err != nil {
		return s.revokeAfterDeliveryFailure(ctx, s.config.PasswordResetTokens, token, err)
	}
	return nil
}

// ResetPassword atomically consumes the one-time token with the host's password
// update/revocation transaction.
func (s *Service) ResetPassword(ctx context.Context, token, password, confirmation string) error {
	if s.config.PasswordResetTokens.Store == nil {
		return ErrPasswordResetUnavailable
	}
	if len(password) < PasswordMinBytes || len(password) > PasswordMaxBytes || password != confirmation {
		return ErrInvalidInput
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("auth: hash replacement password: %w", err)
	}
	return s.config.PasswordResetTokens.Consume(ctx, token, s.config.Now(), func(callbackCtx context.Context, subject string) error {
		return s.config.Accounts.UpdatePasswordAndRevokeAuth(callbackCtx, subject, hash)
	})
}

// RequestEmailVerification sends a host-rendered email only when verification is
// enabled. Unknown addresses and already-verified accounts are intentionally quiet.
func (s *Service) RequestEmailVerification(ctx context.Context, email string) error {
	mode, err := s.verificationMode(ctx)
	if err != nil {
		return err
	}
	if mode == VerificationDisabled {
		return nil
	}
	if s.config.EmailVerifyTokens.Store == nil || s.config.Emails == nil {
		return ErrVerificationUnavailable
	}
	email = normalizeEmail(email)
	if email == "" {
		return nil
	}
	account, err := s.config.Accounts.FindByEmail(ctx, email)
	if errors.Is(err, ErrAccountNotFound) || (err == nil && account.EmailVerified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auth: find verification account: %w", err)
	}
	return s.sendVerification(ctx, account)
}

func (s *Service) sendVerification(ctx context.Context, account Account) error {
	if s.config.EmailVerifyTokens.Store == nil || s.config.Emails == nil {
		return ErrVerificationUnavailable
	}
	expires := s.config.Now().Add(EmailVerificationTTL)
	token, err := s.config.EmailVerifyTokens.Issue(ctx, account.ID, expires)
	if err != nil {
		return err
	}
	if err := s.config.Emails.SendAuthEmail(ctx, AuthEmail{Kind: EmailVerifyAddress, To: account.Email, Token: token, ExpiresAt: expires}); err != nil {
		return s.revokeAfterDeliveryFailure(ctx, s.config.EmailVerifyTokens, token, err)
	}
	return nil
}

// VerifyEmail consumes a verification token and marks the host-owned account
// email verified in the same transaction as token consumption.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	if s.config.EmailVerifyTokens.Store == nil {
		return ErrVerificationUnavailable
	}
	return s.config.EmailVerifyTokens.Consume(ctx, token, s.config.Now(), func(callbackCtx context.Context, subject string) error {
		return s.config.Accounts.MarkEmailVerified(callbackCtx, subject)
	})
}

func (s *Service) revokeAfterDeliveryFailure(ctx context.Context, tokens OneTimeTokens, token string, deliveryErr error) error {
	if revoker, ok := tokens.Store.(OneTimeTokenRevoker); ok {
		if revokeErr := revoker.RevokeOneTimeToken(ctx, TokenDigest(token)); revokeErr != nil {
			return errors.Join(deliveryErr, fmt.Errorf("auth: revoke undelivered token: %w", revokeErr))
		}
	}
	return fmt.Errorf("auth: deliver authentication email: %w", deliveryErr)
}

// OAuthProvider is a verified provider adapter. Complete must exchange the code
// and validate provider-specific signatures/claims/email before returning.
type OAuthProvider interface {
	Name() string
	CallbackMethod() string
	AuthorizationURL(ctx context.Context, state, nonce, verifier, redirectURL string) (string, error)
	Complete(ctx context.Context, code, nonce, verifier, redirectURL string) (ProviderIdentity, error)
}

// ProviderIdentity is trusted only after OAuthProvider.Complete has validated it.
// EmailVerified is true only when that provider explicitly attests to the email;
// it is independent of whether the provider subject itself was authenticated.
type ProviderIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

// ProviderCallbackResult contains server-side callback outcome data for the
// HTTP handler/host redirect adapter. It must never be serialized as a response.
type ProviderCallbackResult struct {
	Account            Account
	Registration       RegistrationAttempt
	DesktopState       string
	DesktopCallbackURL string
}

// BeginProviderLogin generates state, nonce, and PKCE values, then stores all
// sensitive callback state server-side. linkCurrentAccount is only for an
// already-authenticated browser session; otherwise an email conflict becomes a
// pending link requiring password login and an explicit follow-up action. The
// registration attempt carries app-owned invite/terms input only. A desktop
// state binds the provider flow to an already-started native PKCE request.
func (s *Service) BeginProviderLogin(ctx context.Context, providerName, redirectURL string, linkCurrentAccount bool, registration RegistrationAttempt, desktopState string) (string, error) {
	provider, ok := s.config.OAuthProviders[providerName]
	if !ok || s.config.OAuthStates == nil {
		return "", ErrOAuthUnavailable
	}
	registration.Email = ""
	registration.Username = ""
	if !validCallbackURL(redirectURL) {
		return "", ErrInvalidInput
	}
	if desktopState != "" {
		if linkCurrentAccount || s.config.DesktopAuth == nil || !desktopStatePattern.MatchString(desktopState) {
			return "", ErrInvalidDesktopAuth
		}
		exists, err := s.config.DesktopAuth.HasDesktopAuthRequest(ctx, TokenDigest(desktopState), s.config.Now())
		if err != nil || !exists {
			return "", ErrInvalidDesktopAuth
		}
	}
	linkSubject := ""
	if linkCurrentAccount {
		registration = RegistrationAttempt{}
		account, authenticated, err := s.CurrentBrowserAccount(ctx)
		if err != nil {
			return "", err
		}
		if !authenticated {
			return "", ErrInvalidCredentials
		}
		linkSubject = account.ID
	}
	state, err := NewStateToken()
	if err != nil {
		return "", err
	}
	nonce, err := NewPKCEVerifier()
	if err != nil {
		return "", err
	}
	verifier, err := NewPKCEVerifier()
	if err != nil {
		return "", err
	}
	started := s.config.Now()
	expires := started.Add(OAuthStateTTL)
	pending := PendingOAuthState{Provider: providerName, Nonce: nonce, Verifier: verifier, RedirectURL: redirectURL, LinkSubject: linkSubject, Registration: registration, DesktopState: desktopState, StartedAt: started, ExpiresAt: expires}
	saveErr := s.config.OAuthStates.SaveOAuthState(ctx, TokenDigest(state), pending)
	if saveErr != nil {
		return "", fmt.Errorf("auth: save OAuth state: %w", saveErr)
	}
	authorizationURL, err := provider.AuthorizationURL(ctx, state, nonce, verifier, redirectURL)
	if err != nil {
		return "", fmt.Errorf("auth: build %s authorization URL: %w", providerName, err)
	}
	return authorizationURL, nil
}

// CompleteProviderLogin consumes state once, validates the provider callback,
// refuses automatic email-based linking, and delegates new-account eligibility
// and atomic creation/linking to the host adapter.
func (s *Service) CompleteProviderLogin(ctx context.Context, providerName, state, code string) (Account, error) {
	result, err := s.CompleteProviderCallback(ctx, providerName, state, code)
	return result.Account, err
}

// CompleteProviderCallback returns enough server-side context for the host to
// route browser success/errors and for desktop logins to finish the PKCE handoff.
//
//nolint:gocyclo // Keep the single-use state, identity, linking, and verification gates in one auditable transaction.
func (s *Service) CompleteProviderCallback(ctx context.Context, providerName, state, code string) (ProviderCallbackResult, error) {
	provider, ok := s.config.OAuthProviders[providerName]
	if !ok || s.config.OAuthStates == nil {
		return ProviderCallbackResult{}, ErrOAuthUnavailable
	}
	if state == "" || len(state) > 128 || code == "" || len(code) > 4096 {
		return ProviderCallbackResult{}, ErrInvalidOAuthResponse
	}
	pending, found, err := s.config.OAuthStates.ConsumeOAuthState(ctx, TokenDigest(state), s.config.Now())
	if err != nil {
		return ProviderCallbackResult{}, fmt.Errorf("auth: consume OAuth state: %w", err)
	}
	now := s.config.Now()
	started := pending.StartedAt
	if started.IsZero() {
		started = pending.ExpiresAt.Add(-OAuthStateTTL)
	}
	if !found || pending.Provider != providerName || started.Unix() > now.Unix() || now.Unix()-started.Unix() > int64(OAuthStateTTL/time.Second) {
		return ProviderCallbackResult{}, ErrInvalidOAuthResponse
	}
	result := ProviderCallbackResult{Registration: pending.Registration, DesktopState: pending.DesktopState}
	identity, err := provider.Complete(ctx, code, pending.Nonce, pending.Verifier, pending.RedirectURL)
	if err != nil {
		return result, fmt.Errorf("auth: validate %s callback: %w", providerName, err)
	}
	if identity.Provider != providerName || !supportedOAuthProvider(identity.Provider) || identity.Subject == "" || len(identity.Subject) > 255 || hasControl(identity.Subject) {
		return result, ErrInvalidOAuthResponse
	}
	if identity.Email != "" {
		identity.Email = normalizeEmail(identity.Email)
		if identity.Email == "" {
			return result, ErrInvalidOAuthResponse
		}
	} else {
		identity.EmailVerified = false
	}
	if pending.LinkSubject != "" {
		account, findErr := s.config.Accounts.FindByID(ctx, pending.LinkSubject)
		if findErr != nil {
			return result, findErr
		}
		if identity.Email == "" || !constantTimeEqual(normalizeEmail(account.Email), identity.Email) {
			return result, ErrOAuthEmailMismatch
		}
		linkErr := s.config.Accounts.LinkProviderIdentity(ctx, account.ID, providerName, identity.Subject, identity.Email)
		if linkErr != nil {
			return result, fmt.Errorf("auth: link %s identity: %w", providerName, linkErr)
		}
		account, err = s.enforceVerification(ctx, account)
		if err != nil {
			return result, err
		}
		result.Account = account
		return s.finishProviderCallback(ctx, result)
	}
	account, err := s.config.Accounts.FindByProviderIdentity(ctx, providerName, identity.Subject)
	if err == nil {
		account, err = s.enforceVerification(ctx, account)
		if err != nil {
			return result, err
		}
		result.Account = account
		return s.finishProviderCallback(ctx, result)
	}
	if !errors.Is(err, ErrAccountNotFound) {
		return result, fmt.Errorf("auth: find linked provider identity: %w", err)
	}
	if identity.Email == "" {
		return result, ErrInvalidOAuthResponse
	}
	_, err = s.config.Accounts.FindByEmail(ctx, identity.Email)
	if err == nil {
		if s.config.PendingOAuthLinks == nil {
			return result, ErrAccountLinkRequired
		}
		saveErr := s.config.PendingOAuthLinks.SavePendingOAuthLink(ctx, identity, s.config.Now().Add(OAuthStateTTL))
		if saveErr != nil {
			return result, fmt.Errorf("auth: save pending provider link: %w", saveErr)
		}
		return result, ErrAccountLinkRequired
	}
	if !errors.Is(err, ErrAccountNotFound) {
		return result, fmt.Errorf("auth: find provider email: %w", err)
	}
	mode, err := s.verificationMode(ctx)
	if err != nil {
		return result, err
	}
	if !identity.EmailVerified {
		if mode == VerificationDisabled {
			return result, ErrEmailNotVerified
		}
		if s.config.EmailVerifyTokens.Store == nil || s.config.Emails == nil {
			return result, ErrVerificationUnavailable
		}
	}
	registration := pending.Registration
	registration.Email = identity.Email
	registration.Username = ""
	account, err = s.config.Policy.ProvisionProviderAccount(ctx, identity, registration)
	if err != nil {
		return result, err
	}
	if !account.EmailVerified && mode != VerificationDisabled {
		if sendErr := s.sendVerification(ctx, account); sendErr != nil {
			return result, sendErr
		}
	}
	if mode == VerificationRequired && !account.EmailVerified {
		return result, ErrEmailNotVerified
	}
	account, err = s.enforceVerification(ctx, account)
	if err != nil {
		return result, err
	}
	result.Account = account
	return s.finishProviderCallback(ctx, result)
}

func (s *Service) finishProviderCallback(ctx context.Context, result ProviderCallbackResult) (ProviderCallbackResult, error) {
	if result.DesktopState == "" {
		return result, nil
	}
	callbackURL, err := s.IssueDesktopAuthCode(ctx, result.DesktopState, result.Account)
	if err != nil {
		return result, err
	}
	result.DesktopCallbackURL = callbackURL
	return result, nil
}

var (
	ErrInvalidOAuthResponse = errors.New("invalid or expired OAuth response")
	ErrOAuthEmailMismatch   = errors.New("provider-verified email does not match the existing account")
)

// LinkPendingProviderIdentity links a previously verified email-conflict identity
// only to the now-authenticated account with that exact email address.
func (s *Service) LinkPendingProviderIdentity(ctx context.Context) error {
	if s.config.PendingOAuthLinks == nil {
		return ErrOAuthUnavailable
	}
	account, authenticated, err := s.CurrentBrowserAccount(ctx)
	if err != nil {
		return err
	}
	if !authenticated {
		return ErrInvalidCredentials
	}
	return s.config.PendingOAuthLinks.ConsumePendingOAuthLink(ctx, s.config.Now(), func(callbackCtx context.Context, identity ProviderIdentity) error {
		if identity.Email == "" || !constantTimeEqual(normalizeEmail(identity.Email), normalizeEmail(account.Email)) {
			return ErrOAuthEmailMismatch
		}
		return s.config.Accounts.LinkProviderIdentity(callbackCtx, account.ID, identity.Provider, identity.Subject, identity.Email)
	})
}

func (s *Service) enforceVerification(ctx context.Context, account Account) (Account, error) {
	mode, err := s.verificationMode(ctx)
	if err != nil {
		return Account{}, err
	}
	if mode == VerificationRequired && !account.EmailVerified {
		return Account{}, ErrEmailNotVerified
	}
	return account, nil
}

func validUsername(username string) bool {
	if username == "" {
		return true
	}
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, r := range username {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

func normalizeEmail(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 254 {
		return ""
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || !strings.Contains(value, "@") {
		return ""
	}
	return value
}

func validCallbackURL(value string) bool {
	if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	return scheme == "https" || (scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"))
}

var (
	desktopStatePattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pkceChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	opaqueTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func (s *Service) StartDesktopAuth(ctx context.Context, state, challenge, redirectURI string) error {
	if s.config.DesktopAuth == nil || !desktopStatePattern.MatchString(state) || !pkceChallengePattern.MatchString(challenge) || !validDesktopRedirectURI(redirectURI) {
		return ErrInvalidDesktopAuth
	}
	return s.config.DesktopAuth.CreateDesktopAuthRequest(ctx, TokenDigest(state), DesktopAuthRequest{
		CodeChallenge: challenge, RedirectURI: redirectURI, ExpiresAt: s.config.Now().Add(DesktopAuthRequestTTL),
	})
}

// IssueDesktopAuthCode consumes one pending loopback request and redirects only
// to its exactly validated, ephemeral 127.0.0.1 callback.
func (s *Service) IssueDesktopAuthCode(ctx context.Context, state string, account Account) (string, error) {
	if s.config.DesktopAuth == nil || !desktopStatePattern.MatchString(state) || account.ID == "" {
		return "", ErrInvalidDesktopAuth
	}
	var callbackURL string
	err := s.config.DesktopAuth.ConsumeDesktopAuthRequest(ctx, TokenDigest(state), s.config.Now(), func(callbackCtx context.Context, request DesktopAuthRequest) error {
		if request.ExpiresAt.Unix() < s.config.Now().Unix() || !validDesktopRedirectURI(request.RedirectURI) || !pkceChallengePattern.MatchString(request.CodeChallenge) {
			return ErrInvalidDesktopAuth
		}
		code, err := NewOpaqueToken()
		if err != nil {
			return err
		}
		expires := s.config.Now().Add(DesktopAuthCodeTTL)
		if storeErr := s.config.DesktopAuth.CreateDesktopAuthCode(callbackCtx, code.Digest, DesktopAuthCode{
			Subject: account.ID, AuthVersion: account.AuthVersion, CodeChallenge: request.CodeChallenge, ExpiresAt: expires,
		}); storeErr != nil {
			return storeErr
		}
		callbackURL, err = desktopCallbackURL(request.RedirectURI, code.Value, state)
		return err
	})
	if err != nil {
		return "", ErrInvalidDesktopAuth
	}
	if callbackURL == "" {
		return "", ErrInvalidDesktopAuth
	}
	return callbackURL, nil
}

// ExchangeDesktopAuthCode consumes the one-time PKCE code and creates a separate
// opaque bearer token. Only its digest is persisted; the host store must join the
// bearer insertion to the code-consumption transaction.
func (s *Service) ExchangeDesktopAuthCode(ctx context.Context, code, verifier string) (string, time.Time, error) {
	if s.config.DesktopAuth == nil || s.config.DesktopBearers == nil || !opaqueTokenPattern.MatchString(code) {
		return "", time.Time{}, ErrInvalidDesktopAuth
	}
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		return "", time.Time{}, ErrInvalidDesktopAuth
	}
	var bearerValue string
	var bearerExpiry time.Time
	err = s.config.DesktopAuth.ConsumeDesktopAuthCode(ctx, TokenDigest(code), s.config.Now(), func(callbackCtx context.Context, authCode DesktopAuthCode) error {
		if authCode.ExpiresAt.Unix() < s.config.Now().Unix() || len(authCode.CodeChallenge) != len(challenge) || subtle.ConstantTimeCompare([]byte(authCode.CodeChallenge), []byte(challenge)) != 1 {
			return ErrInvalidDesktopAuth
		}
		account, findErr := s.config.Accounts.FindByID(callbackCtx, authCode.Subject)
		if findErr != nil || account.AuthVersion != authCode.AuthVersion {
			return ErrInvalidDesktopAuth
		}
		opaqueToken, tokenErr := NewOpaqueToken()
		if tokenErr != nil {
			return tokenErr
		}
		bearerExpiry = s.config.Now().Add(s.config.DesktopBearerLifetime)
		if storeErr := s.config.DesktopBearers.StoreDesktopBearer(callbackCtx, opaqueToken.Digest, DesktopBearer{Subject: account.ID, AuthVersion: account.AuthVersion, ExpiresAt: bearerExpiry}); storeErr != nil {
			return storeErr
		}
		bearerValue = opaqueToken.Value
		return nil
	})
	if err != nil || bearerValue == "" {
		return "", time.Time{}, ErrInvalidDesktopAuth
	}
	return bearerValue, bearerExpiry, nil
}

func (s *Service) ResolveDesktopBearer(ctx context.Context, token string) (Account, bool, error) {
	if s.config.DesktopBearers == nil || !opaqueTokenPattern.MatchString(token) {
		return Account{}, false, nil
	}
	bearer, ok, err := s.config.DesktopBearers.ResolveDesktopBearer(ctx, TokenDigest(token), s.config.Now())
	if err != nil || !ok {
		return Account{}, false, err
	}
	account, err := s.config.Accounts.FindByID(ctx, bearer.Subject)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return Account{}, false, nil
		}
		return Account{}, false, err
	}
	return account, account.AuthVersion == bearer.AuthVersion && bearer.ExpiresAt.Unix() >= s.config.Now().Unix(), nil
}

func validDesktopRedirectURI(value string) bool {
	if len(value) > 256 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/callback" {
		return false
	}
	port := parsed.Port()
	if port == "" {
		return false
	}
	var valuePort int
	if _, err := fmt.Sscanf(port, "%d", &valuePort); err != nil || valuePort < 1024 || valuePort > 65535 {
		return false
	}
	return true
}

func desktopCallbackURL(redirectURI, code, state string) (string, error) {
	if !validDesktopRedirectURI(redirectURI) {
		return "", ErrInvalidDesktopAuth
	}
	return redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state), nil
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
