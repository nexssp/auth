package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPassword = "long-enough-test-password"

type memoryAccounts struct {
	mu         sync.Mutex
	byID       map[string]Account
	identities map[string]string
	next       int
}

func newMemoryAccounts() *memoryAccounts {
	return &memoryAccounts{byID: map[string]Account{}, identities: map[string]string{}}
}

func (store *memoryAccounts) FindByIdentifier(_ context.Context, identifier string) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, account := range store.byID {
		if strings.EqualFold(account.Email, strings.TrimSpace(identifier)) || strings.EqualFold(account.Username, strings.TrimSpace(identifier)) {
			return account, nil
		}
	}
	return Account{}, ErrAccountNotFound
}

func (store *memoryAccounts) FindByEmail(_ context.Context, email string) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, account := range store.byID {
		if strings.EqualFold(account.Email, email) {
			return account, nil
		}
	}
	return Account{}, ErrAccountNotFound
}

func (store *memoryAccounts) FindByID(_ context.Context, id string) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[id]
	if !ok {
		return Account{}, ErrAccountNotFound
	}
	return account, nil
}

func (store *memoryAccounts) CreatePasswordAccount(_ context.Context, input NewPasswordAccount) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, account := range store.byID {
		if strings.EqualFold(account.Email, input.Email) {
			return Account{}, errors.New("duplicate email")
		}
	}
	store.next++
	account := Account{ID: fmt.Sprintf("user-%d", store.next), Email: input.Email, Username: input.Username, PasswordHash: input.PasswordHash, EmailVerified: input.EmailVerified, AuthVersion: 1}
	store.byID[account.ID] = account
	return account, nil
}

func (store *memoryAccounts) UpdatePasswordAndRevokeAuth(_ context.Context, subject, passwordHash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[subject]
	if !ok {
		return ErrAccountNotFound
	}
	account.PasswordHash = passwordHash
	account.AuthVersion++
	store.byID[subject] = account
	return nil
}

func (store *memoryAccounts) MarkEmailVerified(_ context.Context, subject string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[subject]
	if !ok {
		return ErrAccountNotFound
	}
	account.EmailVerified = true
	store.byID[subject] = account
	return nil
}

func identityKey(provider, subject string) string { return provider + ":" + subject }

func (store *memoryAccounts) FindByProviderIdentity(_ context.Context, provider, subject string) (Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, ok := store.identities[identityKey(provider, subject)]
	if !ok {
		return Account{}, ErrAccountNotFound
	}
	return store.byID[id], nil
}

func (store *memoryAccounts) LinkProviderIdentity(_ context.Context, userID, provider, subject, email string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.byID[userID]; !ok {
		return ErrAccountNotFound
	}
	key := identityKey(provider, subject)
	if existing, ok := store.identities[key]; ok && existing != userID {
		return errors.New("provider identity already linked")
	}
	store.identities[key] = userID
	return nil
}

func (store *memoryAccounts) seedPassword(t *testing.T, email, username string, verified bool) Account {
	t.Helper()
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.CreatePasswordAccount(context.Background(), NewPasswordAccount{Email: email, Username: username, PasswordHash: hash, EmailVerified: verified})
	if err != nil {
		t.Fatal(err)
	}
	return account
}

type memoryPolicy struct {
	mu                sync.Mutex
	mode              EmailVerificationMode
	modeErr           error
	registrationErr   error
	registrationCalls []RegistrationAttempt
	provisionCalls    []ProviderIdentity
	provisionAttempts []RegistrationAttempt
	accounts          *memoryAccounts
}

func (policy *memoryPolicy) EmailVerificationMode(context.Context) (EmailVerificationMode, error) {
	policy.mu.Lock()
	defer policy.mu.Unlock()
	return policy.mode, policy.modeErr
}

func (policy *memoryPolicy) CreatePasswordAccount(ctx context.Context, attempt RegistrationAttempt, input NewPasswordAccount) (Account, error) {
	policy.mu.Lock()
	policy.registrationCalls = append(policy.registrationCalls, attempt)
	registrationErr := policy.registrationErr
	policy.mu.Unlock()
	if registrationErr != nil {
		return Account{}, registrationErr
	}
	return policy.accounts.CreatePasswordAccount(ctx, input)
}

func (policy *memoryPolicy) ProvisionProviderAccount(ctx context.Context, identity ProviderIdentity, attempt RegistrationAttempt) (Account, error) {
	policy.mu.Lock()
	policy.provisionCalls = append(policy.provisionCalls, identity)
	policy.provisionAttempts = append(policy.provisionAttempts, attempt)
	registrationErr := policy.registrationErr
	policy.mu.Unlock()
	if registrationErr != nil {
		return Account{}, registrationErr
	}
	if account, err := policy.accounts.FindByEmail(ctx, identity.Email); err == nil {
		return Account{}, fmt.Errorf("host policy: registration denied for existing email %s", account.Email)
	}
	account, err := policy.accounts.CreatePasswordAccount(ctx, NewPasswordAccount{Email: identity.Email, Username: identity.Provider + "_external", EmailVerified: identity.EmailVerified})
	if err != nil {
		return Account{}, err
	}
	if err := policy.accounts.LinkProviderIdentity(ctx, account.ID, identity.Provider, identity.Subject, identity.Email); err != nil {
		return Account{}, err
	}
	return account, nil
}

type memorySessions struct {
	mu      sync.Mutex
	session BrowserSession
	active  bool
}

func (store *memorySessions) EstablishBrowserSession(_ context.Context, session BrowserSession) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.session, store.active = session, true
	return nil
}

func (store *memorySessions) CurrentBrowserSession(context.Context) (BrowserSession, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.session, store.active, nil
}

func (store *memorySessions) EndBrowserSession(context.Context) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.active = false
	store.session = BrowserSession{}
	return nil
}

type memoryTokens struct {
	mu    sync.Mutex
	items map[string]memoryToken
}

type memoryToken struct {
	subject string
	expires time.Time
}

func newMemoryTokens() *memoryTokens { return &memoryTokens{items: map[string]memoryToken{}} }
func (store *memoryTokens) InsertOneTimeToken(_ context.Context, digest, subject string, expires time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[digest] = memoryToken{subject: subject, expires: expires}
	return nil
}

func (store *memoryTokens) ConsumeOneTimeToken(ctx context.Context, digest string, now time.Time, apply func(context.Context, string) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	item, ok := store.items[digest]
	if !ok || !item.expires.After(now) {
		return ErrInvalidOneTimeToken
	}
	if err := apply(ctx, item.subject); err != nil {
		return err
	}
	delete(store.items, digest)
	return nil
}

func (store *memoryTokens) RevokeOneTimeToken(_ context.Context, digest string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.items, digest)
	return nil
}

type memoryEmails struct {
	mu       sync.Mutex
	messages []AuthEmail
	err      error
}

func (sender *memoryEmails) SendAuthEmail(_ context.Context, message AuthEmail) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.messages = append(sender.messages, message)
	return sender.err
}

func (sender *memoryEmails) latest(kind string) (AuthEmail, bool) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	for i := len(sender.messages) - 1; i >= 0; i-- {
		if sender.messages[i].Kind == kind {
			return sender.messages[i], true
		}
	}
	return AuthEmail{}, false
}

type memoryOAuthStates struct {
	mu    sync.Mutex
	items map[string]PendingOAuthState
}

func newMemoryOAuthStates() *memoryOAuthStates {
	return &memoryOAuthStates{items: map[string]PendingOAuthState{}}
}

func (store *memoryOAuthStates) SaveOAuthState(_ context.Context, digest string, pending PendingOAuthState) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[digest] = pending
	return nil
}

func (store *memoryOAuthStates) ConsumeOAuthState(_ context.Context, digest string, now time.Time) (PendingOAuthState, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.items[digest]
	if !ok || pending.ExpiresAt.Unix() < now.Unix() {
		delete(store.items, digest)
		return PendingOAuthState{}, false, nil
	}
	delete(store.items, digest)
	return pending, true, nil
}

type memoryPendingLinks struct {
	mu       sync.Mutex
	identity ProviderIdentity
	expires  time.Time
	exists   bool
}

func (store *memoryPendingLinks) SavePendingOAuthLink(_ context.Context, identity ProviderIdentity, expires time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.identity, store.expires, store.exists = identity, expires, true
	return nil
}

func (store *memoryPendingLinks) ConsumePendingOAuthLink(ctx context.Context, now time.Time, apply func(context.Context, ProviderIdentity) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.exists || store.expires.Unix() < now.Unix() {
		store.exists = false
		return ErrInvalidOAuthResponse
	}
	if err := apply(ctx, store.identity); err != nil {
		return err
	}
	store.exists = false
	store.identity = ProviderIdentity{}
	return nil
}

type memoryDesktopAuth struct {
	requestMu sync.Mutex
	codeMu    sync.Mutex
	requests  map[string]DesktopAuthRequest
	codes     map[string]DesktopAuthCode
}

func newMemoryDesktopAuth() *memoryDesktopAuth {
	return &memoryDesktopAuth{requests: map[string]DesktopAuthRequest{}, codes: map[string]DesktopAuthCode{}}
}

func (store *memoryDesktopAuth) CreateDesktopAuthRequest(_ context.Context, digest string, request DesktopAuthRequest) error {
	store.requestMu.Lock()
	defer store.requestMu.Unlock()
	if _, exists := store.requests[digest]; exists {
		return errors.New("duplicate state")
	}
	store.requests[digest] = request
	return nil
}

func (store *memoryDesktopAuth) HasDesktopAuthRequest(_ context.Context, digest string, now time.Time) (bool, error) {
	store.requestMu.Lock()
	defer store.requestMu.Unlock()
	request, ok := store.requests[digest]
	return ok && request.ExpiresAt.Unix() >= now.Unix(), nil
}

func (store *memoryDesktopAuth) ConsumeDesktopAuthRequest(ctx context.Context, digest string, now time.Time, apply func(context.Context, DesktopAuthRequest) error) error {
	store.requestMu.Lock()
	defer store.requestMu.Unlock()
	request, ok := store.requests[digest]
	if !ok || request.ExpiresAt.Unix() < now.Unix() {
		return ErrInvalidDesktopAuth
	}
	if err := apply(ctx, request); err != nil {
		return err
	}
	delete(store.requests, digest)
	return nil
}

func (store *memoryDesktopAuth) CreateDesktopAuthCode(_ context.Context, digest string, code DesktopAuthCode) error {
	store.codeMu.Lock()
	defer store.codeMu.Unlock()
	store.codes[digest] = code
	return nil
}

func (store *memoryDesktopAuth) ConsumeDesktopAuthCode(ctx context.Context, digest string, now time.Time, apply func(context.Context, DesktopAuthCode) error) error {
	store.codeMu.Lock()
	defer store.codeMu.Unlock()
	code, ok := store.codes[digest]
	if !ok || code.ExpiresAt.Unix() < now.Unix() {
		return ErrInvalidDesktopAuth
	}
	if err := apply(ctx, code); err != nil {
		return err
	}
	delete(store.codes, digest)
	return nil
}

type memoryBearers struct {
	mu    sync.Mutex
	items map[string]DesktopBearer
}

func newMemoryBearers() *memoryBearers { return &memoryBearers{items: map[string]DesktopBearer{}} }
func (store *memoryBearers) StoreDesktopBearer(_ context.Context, digest string, bearer DesktopBearer) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[digest] = bearer
	return nil
}

func (store *memoryBearers) ResolveDesktopBearer(_ context.Context, digest string, now time.Time) (DesktopBearer, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	bearer, ok := store.items[digest]
	return bearer, ok && bearer.ExpiresAt.Unix() >= now.Unix(), nil
}

func (store *memoryBearers) RevokeDesktopBearer(_ context.Context, digest string, _ time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, ok := store.items[digest]
	delete(store.items, digest)
	return ok, nil
}

type fakeProvider struct {
	name        string
	identity    ProviderIdentity
	method      string
	authURL     string
	completeErr error
	calls       int
}

func (provider *fakeProvider) Name() string {
	if provider.name != "" {
		return provider.name
	}
	return "google"
}

func (provider *fakeProvider) CallbackMethod() string {
	if provider.method == "" {
		return http.MethodGet
	}
	return provider.method
}

func (provider *fakeProvider) AuthorizationURL(_ context.Context, state, _, _, redirect string) (string, error) {
	if provider.authURL != "" {
		return provider.authURL + "?state=" + url.QueryEscape(state), nil
	}
	authorizationURL := "https://accounts.google.com/o/oauth2/v2/auth"
	if provider.Name() == "facebook" {
		authorizationURL = "https://www.facebook.com/v27.0/dialog/oauth"
	}
	return authorizationURL + "?state=" + url.QueryEscape(state) + "&redirect_uri=" + url.QueryEscape(redirect), nil
}

func (provider *fakeProvider) Complete(_ context.Context, _, _, _, _ string) (ProviderIdentity, error) {
	provider.calls++
	return provider.identity, provider.completeErr
}

type fakeBoundary struct {
	calls []BoundaryOperation
	err   error
}

func (boundary *fakeBoundary) AuthorizeAuthRequest(_ context.Context, operation BoundaryOperation, _ *http.Request, _ string) error {
	boundary.calls = append(boundary.calls, operation)
	return boundary.err
}

type serviceHarness struct {
	service      *Service
	accounts     *memoryAccounts
	policy       *memoryPolicy
	sessions     *memorySessions
	resetTokens  *memoryTokens
	verifyTokens *memoryTokens
	emails       *memoryEmails
	oauthStates  *memoryOAuthStates
	pendingLinks *memoryPendingLinks
	desktop      *memoryDesktopAuth
	bearers      *memoryBearers
	now          time.Time
}

func newServiceHarness(t *testing.T, mode EmailVerificationMode, provider *fakeProvider) *serviceHarness {
	t.Helper()
	now := time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)
	accounts, sessions := newMemoryAccounts(), &memorySessions{}
	policy := &memoryPolicy{mode: mode, accounts: accounts}
	resetTokens, verifyTokens, emails := newMemoryTokens(), newMemoryTokens(), &memoryEmails{}
	oauthStates, pendingLinks := newMemoryOAuthStates(), &memoryPendingLinks{}
	desktop, bearers := newMemoryDesktopAuth(), newMemoryBearers()
	providers := map[string]OAuthProvider{}
	if provider != nil {
		providers[provider.Name()] = provider
	}
	service, err := NewService(ServiceConfig{
		Accounts: accounts, Policy: policy, BrowserSessions: sessions,
		BrowserSessionLifetime: func(context.Context, Account) (time.Duration, error) { return 7 * 24 * time.Hour, nil },
		Emails:                 emails, PasswordResetTokens: OneTimeTokens{Store: resetTokens}, EmailVerifyTokens: OneTimeTokens{Store: verifyTokens},
		OAuthStates: oauthStates, PendingOAuthLinks: pendingLinks, OAuthProviders: providers,
		DesktopAuth: desktop, DesktopBearers: bearers, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &serviceHarness{service: service, accounts: accounts, policy: policy, sessions: sessions, resetTokens: resetTokens, verifyTokens: verifyTokens, emails: emails, oauthStates: oauthStates, pendingLinks: pendingLinks, desktop: desktop, bearers: bearers, now: now}
}

func TestVerificationModesPreserveImmediateSignupUnlessHostChoosesGate(t *testing.T) {
	for _, test := range []struct {
		mode                               EmailVerificationMode
		verified, authenticated, emailSent bool
	}{
		{VerificationDisabled, true, true, false},
		{VerificationOptional, false, true, true},
		{VerificationRequired, false, false, true},
	} {
		t.Run(string(test.mode), func(t *testing.T) {
			h := newServiceHarness(t, test.mode, nil)
			attempt := RegistrationAttempt{Email: " Keon@Example.Test ", Username: "keon", InviteCode: "invite-stub", TermsAccepted: true}
			account, err := h.service.RegisterPassword(context.Background(), attempt, testPassword, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			if account.EmailVerified != test.verified {
				t.Fatalf("verified=%v, want %v", account.EmailVerified, test.verified)
			}
			if len(h.policy.registrationCalls) != 1 || !h.policy.registrationCalls[0].TermsAccepted || h.policy.registrationCalls[0].InviteCode != "invite-stub" {
				t.Fatal("host registration policy did not receive app-owned terms/invite data")
			}
			_, emailSent := h.emails.latest(EmailVerifyAddress)
			if emailSent != test.emailSent {
				t.Fatalf("verification email sent=%v, want %v", emailSent, test.emailSent)
			}
			_, loginErr := h.service.AuthenticatePassword(context.Background(), "keon", testPassword)
			if test.mode == VerificationRequired && !test.verified {
				if !errors.Is(loginErr, ErrEmailNotVerified) {
					t.Fatalf("login error=%v, want ErrEmailNotVerified", loginErr)
				}
			} else if loginErr != nil {
				t.Fatalf("login: %v", loginErr)
			}
			if test.emailSent {
				message, ok := h.emails.latest(EmailVerifyAddress)
				if !ok {
					t.Fatal("missing verification event")
				}
				if err := h.service.VerifyEmail(context.Background(), message.Token); err != nil {
					t.Fatalf("verify email: %v", err)
				}
				updated, _ := h.accounts.FindByID(context.Background(), account.ID)
				if !updated.EmailVerified {
					t.Fatal("verification did not update account")
				}
				if err := h.service.VerifyEmail(context.Background(), message.Token); !errors.Is(err, ErrInvalidOneTimeToken) {
					t.Fatalf("token replay error=%v", err)
				}
			}
		})
	}
}

func TestVerificationModeMustBeExplicit(t *testing.T) {
	h := newServiceHarness(t, "", nil)
	_, err := h.service.RegisterPassword(context.Background(), RegistrationAttempt{Email: "a@example.test"}, testPassword, testPassword)
	if !errors.Is(err, ErrVerificationModeUnset) {
		t.Fatalf("got %v, want explicit mode error", err)
	}
}

func TestHostRegistrationPolicyCanDenyBeforeAccountCreation(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	h.policy.registrationErr = errors.New("invite required")
	_, err := h.service.RegisterPassword(context.Background(), RegistrationAttempt{Email: "a@example.test", InviteCode: "bad"}, testPassword, testPassword)
	if err == nil {
		t.Fatal("expected host policy denial")
	}
	if len(h.accounts.byID) != 0 {
		t.Fatal("account created despite host policy denial")
	}
}

func TestPasswordResetUsesSingleUseTokenAndVersionedRevocation(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	account := h.accounts.seedPassword(t, "keon@example.test", "keon", true)
	if err := h.service.RequestPasswordReset(context.Background(), account.Email); err != nil {
		t.Fatal(err)
	}
	message, ok := h.emails.latest(EmailPasswordReset)
	if !ok || message.Token == "" {
		t.Fatal("reset notification missing token")
	}
	if err := h.service.ResetPassword(context.Background(), message.Token, "another-long-password", "another-long-password"); err != nil {
		t.Fatal(err)
	}
	updated, _ := h.accounts.FindByID(context.Background(), account.ID)
	if updated.AuthVersion != account.AuthVersion+1 {
		t.Fatalf("auth version=%d, want %d", updated.AuthVersion, account.AuthVersion+1)
	}
	if _, err := h.service.AuthenticatePassword(context.Background(), account.Email, testPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password error=%v", err)
	}
	if _, err := h.service.AuthenticatePassword(context.Background(), account.Email, "another-long-password"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
	if err := h.service.ResetPassword(context.Background(), message.Token, "another-long-password", "another-long-password"); !errors.Is(err, ErrInvalidOneTimeToken) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestPasswordResetRequestDoesNotRevealUnknownEmail(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	if err := h.service.RequestPasswordReset(context.Background(), "nobody@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.emails.latest(EmailPasswordReset); ok {
		t.Fatal("sent reset mail for unknown account")
	}
}

func TestOAuthLoginCreatesHostOwnedAccountAndConsumesStateOnce(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "google-sub", Email: "new@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	redirect := "https://nexss.example.test/auth/oauth/google/callback"
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "google", redirect, false, RegistrationAttempt{}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL lacks state: %s", authorizationURL)
	}
	account, err := h.service.CompleteProviderLogin(context.Background(), "google", state, "code")
	if err != nil {
		t.Fatal(err)
	}
	linked, err := h.accounts.FindByProviderIdentity(context.Background(), "google", "google-sub")
	if err != nil || linked.ID != account.ID {
		t.Fatalf("provider account link: account=%+v err=%v", linked, err)
	}
	if len(h.policy.provisionCalls) != 1 {
		t.Fatal("new provider account did not go through host provisioner")
	}
	if _, err := h.service.CompleteProviderLogin(context.Background(), "google", state, "code"); !errors.Is(err, ErrInvalidOAuthResponse) {
		t.Fatalf("replayed state error=%v", err)
	}
}

func TestFacebookUnverifiedEmailSignupFollowsHostVerificationMode(t *testing.T) {
	for _, test := range []struct {
		mode          EmailVerificationMode
		wantErr       error
		wantCreated   bool
		wantEmailSent bool
	}{
		{mode: VerificationDisabled, wantErr: ErrEmailNotVerified},
		{mode: VerificationOptional, wantCreated: true, wantEmailSent: true},
		{mode: VerificationRequired, wantErr: ErrEmailNotVerified, wantCreated: true, wantEmailSent: true},
	} {
		t.Run(string(test.mode), func(t *testing.T) {
			provider := &fakeProvider{name: "facebook", identity: ProviderIdentity{Provider: "facebook", Subject: "meta-user-42", Email: "new@example.test"}}
			h := newServiceHarness(t, test.mode, provider)
			redirect := "https://nexss.example.test/auth/oauth/facebook/callback"
			authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "facebook", redirect, false, RegistrationAttempt{}, "")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(authorizationURL)
			if err != nil {
				t.Fatal(err)
			}
			result, err := h.service.CompleteProviderCallback(context.Background(), "facebook", parsed.Query().Get("state"), "code")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("callback error=%v, want %v", err, test.wantErr)
			}
			account, findErr := h.accounts.FindByEmail(context.Background(), "new@example.test")
			if (findErr == nil) != test.wantCreated {
				t.Fatalf("account created=%v, want %v (err=%v)", findErr == nil, test.wantCreated, findErr)
			}
			if test.wantCreated && (account.EmailVerified || len(h.policy.provisionCalls) != 1) {
				t.Fatalf("unverified provider account=%+v, provision calls=%d", account, len(h.policy.provisionCalls))
			}
			_, emailSent := h.emails.latest(EmailVerifyAddress)
			if emailSent != test.wantEmailSent {
				t.Fatalf("verification email sent=%v, want %v", emailSent, test.wantEmailSent)
			}
			if test.mode == VerificationOptional && (result.Account.ID == "" || result.Account.EmailVerified) {
				t.Fatalf("optional verification callback result=%+v", result)
			}
		})
	}
}

func TestFacebookLinkedIdentityCanSignInWithoutEmailClaim(t *testing.T) {
	provider := &fakeProvider{name: "facebook", identity: ProviderIdentity{Provider: "facebook", Subject: "meta-linked-user"}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	account := h.accounts.seedPassword(t, "linked@example.test", "linked", true)
	if err := h.accounts.LinkProviderIdentity(context.Background(), account.ID, "facebook", "meta-linked-user", ""); err != nil {
		t.Fatal(err)
	}
	redirect := "https://nexss.example.test/auth/oauth/facebook/callback"
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "facebook", redirect, false, RegistrationAttempt{}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	result, err := h.service.CompleteProviderCallback(context.Background(), "facebook", parsed.Query().Get("state"), "code")
	if err != nil || result.Account.ID != account.ID {
		t.Fatalf("callback account=%+v err=%v", result.Account, err)
	}
}

func TestFacebookEmailConflictStillRequiresExplicitAuthenticatedLink(t *testing.T) {
	provider := &fakeProvider{name: "facebook", identity: ProviderIdentity{Provider: "facebook", Subject: "meta-conflict", Email: "existing@example.test"}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	existing := h.accounts.seedPassword(t, "existing@example.test", "existing", true)
	redirect := "https://nexss.example.test/auth/oauth/facebook/callback"
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "facebook", redirect, false, RegistrationAttempt{}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	if _, err := h.service.CompleteProviderCallback(context.Background(), "facebook", parsed.Query().Get("state"), "code"); !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("callback error=%v, want explicit link", err)
	}
	if _, err := h.accounts.FindByProviderIdentity(context.Background(), "facebook", "meta-conflict"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatal("Facebook identity was automatically linked by email")
	}
	if err := h.service.StartBrowserSession(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	if err := h.service.LinkPendingProviderIdentity(context.Background()); err != nil {
		t.Fatalf("authenticated explicit link failed: %v", err)
	}
	linked, err := h.accounts.FindByProviderIdentity(context.Background(), "facebook", "meta-conflict")
	if err != nil || linked.ID != existing.ID {
		t.Fatalf("linked account=%+v err=%v", linked, err)
	}
}

func TestOAuthEmailConflictNeverAutoLinksAndRequiresAuthenticatedLink(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "google-conflict", Email: "existing@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	existing := h.accounts.seedPassword(t, "existing@example.test", "existing", true)
	redirect := "https://nexss.example.test/auth/oauth/google/callback"
	begin, err := h.service.BeginProviderLogin(context.Background(), "google", redirect, false, RegistrationAttempt{}, "")
	if err != nil {
		t.Fatal(err)
	}
	state, _ := url.Parse(begin)
	if _, err := h.service.CompleteProviderLogin(context.Background(), "google", state.Query().Get("state"), "code"); !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("expected explicit link step, got %v", err)
	}
	if _, err := h.accounts.FindByProviderIdentity(context.Background(), "google", "google-conflict"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatal("identity was automatically linked by email")
	}
	if err := h.service.StartBrowserSession(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	if err := h.service.LinkPendingProviderIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	linked, err := h.accounts.FindByProviderIdentity(context.Background(), "google", "google-conflict")
	if err != nil || linked.ID != existing.ID {
		t.Fatalf("explicit link failed: account=%+v err=%v", linked, err)
	}
}

func TestOAuthLinkingRequiresMatchingVerifiedEmail(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "other-email", Email: "different@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	account := h.accounts.seedPassword(t, "owner@example.test", "owner", true)
	if err := h.service.StartBrowserSession(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	begin, err := h.service.BeginProviderLogin(context.Background(), "google", "https://nexss.example.test/auth/oauth/google/callback", true, RegistrationAttempt{}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(begin)
	if _, err := h.service.CompleteProviderLogin(context.Background(), "google", parsed.Query().Get("state"), "code"); !errors.Is(err, ErrOAuthEmailMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestDesktopPKCEHandoffIssuesBearerSeparateFromBrowserSession(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	account := h.accounts.seedPassword(t, "desktop@example.test", "desktop", true)
	state, err := NewStateToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	redirect := "http://127.0.0.1:24567/callback"
	if err := h.service.StartDesktopAuth(context.Background(), state, challenge, redirect); err != nil {
		t.Fatal(err)
	}
	if err := h.service.StartBrowserSession(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	callback, err := h.service.IssueDesktopAuthCode(context.Background(), state, account)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.Host != "127.0.0.1:24567" || parsed.Query().Get("state") != state {
		t.Fatalf("unexpected loopback callback: %s", callback)
	}
	code := parsed.Query().Get("code")
	if _, _, err := h.service.ExchangeDesktopAuthCode(context.Background(), code, strings.Repeat("x", 43)); !errors.Is(err, ErrInvalidDesktopAuth) {
		t.Fatalf("wrong verifier error=%v", err)
	}
	token, expires, err := h.service.ExchangeDesktopAuthCode(context.Background(), code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 || !expires.Equal(h.now.Add(DesktopBearerTTL)) {
		t.Fatalf("bad token lifetime: len=%d expires=%s", len(token), expires)
	}
	bearer, ok := h.bearers.items[TokenDigest(token)]
	if !ok || bearer.Subject != account.ID {
		t.Fatal("bearer token digest was not stored")
	}
	if _, exists := h.bearers.items[token]; exists {
		t.Fatal("plaintext bearer token was persisted")
	}
	resolved, ok, err := h.service.ResolveDesktopBearer(context.Background(), token)
	if err != nil || !ok || resolved.ID != account.ID {
		t.Fatalf("resolve bearer: account=%+v ok=%v err=%v", resolved, ok, err)
	}
	session, active, err := h.sessions.CurrentBrowserSession(context.Background())
	if err != nil || !active || session.Subject != account.ID {
		t.Fatal("browser session and desktop bearer were not separate")
	}
}

func TestDesktopRejectsNonLoopbackRedirectsAndExpiredRequests(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	state, _ := NewStateToken()
	verifier, _ := NewPKCEVerifier()
	challenge, _ := PKCEChallenge(verifier)
	for _, redirect := range []string{"https://127.0.0.1:12345/callback", "http://127.0.0.1:12345/other", "http://127.0.0.1:12345/callback?next=https://evil.test"} {
		if err := h.service.StartDesktopAuth(context.Background(), state, challenge, redirect); !errors.Is(err, ErrInvalidDesktopAuth) {
			t.Fatalf("redirect %q err=%v", redirect, err)
		}
	}
}

func TestDesktopExpiryIsInclusiveAtExactSecond(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	account := h.accounts.seedPassword(t, "desktop-boundary@example.test", "desktop-boundary", true)
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		t.Fatal(err)
	}

	requestState := strings.Repeat("a", 64)
	h.desktop.requests[TokenDigest(requestState)] = DesktopAuthRequest{
		CodeChallenge: challenge,
		RedirectURI:   "http://127.0.0.1:24567/callback",
		ExpiresAt:     h.now,
	}
	if _, err := h.service.IssueDesktopAuthCode(context.Background(), requestState, account); err != nil {
		t.Fatalf("request at exact expiry was rejected: %v", err)
	}

	code := strings.Repeat("b", 43)
	h.desktop.codes[TokenDigest(code)] = DesktopAuthCode{
		Subject: account.ID, AuthVersion: account.AuthVersion,
		CodeChallenge: challenge, ExpiresAt: h.now,
	}
	if _, _, err := h.service.ExchangeDesktopAuthCode(context.Background(), code, verifier); err != nil {
		t.Fatalf("code at exact expiry was rejected: %v", err)
	}

	bearer := strings.Repeat("c", 43)
	h.bearers.items[TokenDigest(bearer)] = DesktopBearer{
		Subject: account.ID, AuthVersion: account.AuthVersion, ExpiresAt: h.now,
	}
	if _, ok, err := h.service.ResolveDesktopBearer(context.Background(), bearer); err != nil || !ok {
		t.Fatalf("bearer at exact expiry: ok=%v err=%v", ok, err)
	}

	expiredRequestState := strings.Repeat("d", 64)
	h.desktop.requests[TokenDigest(expiredRequestState)] = DesktopAuthRequest{
		CodeChallenge: challenge,
		RedirectURI:   "http://127.0.0.1:24567/callback",
		ExpiresAt:     h.now.Add(-time.Second),
	}
	if _, err := h.service.IssueDesktopAuthCode(context.Background(), expiredRequestState, account); !errors.Is(err, ErrInvalidDesktopAuth) {
		t.Fatalf("request one second past expiry err=%v, want ErrInvalidDesktopAuth", err)
	}

	expiredCode := strings.Repeat("e", 43)
	h.desktop.codes[TokenDigest(expiredCode)] = DesktopAuthCode{
		Subject: account.ID, AuthVersion: account.AuthVersion,
		CodeChallenge: challenge, ExpiresAt: h.now.Add(-time.Second),
	}
	if _, _, err := h.service.ExchangeDesktopAuthCode(context.Background(), expiredCode, verifier); !errors.Is(err, ErrInvalidDesktopAuth) {
		t.Fatalf("code one second past expiry err=%v, want ErrInvalidDesktopAuth", err)
	}

	expiredBearer := strings.Repeat("f", 43)
	h.bearers.items[TokenDigest(expiredBearer)] = DesktopBearer{
		Subject: account.ID, AuthVersion: account.AuthVersion, ExpiresAt: h.now.Add(-time.Second),
	}
	if _, ok, err := h.service.ResolveDesktopBearer(context.Background(), expiredBearer); err != nil || ok {
		t.Fatalf("bearer one second past expiry: ok=%v err=%v", ok, err)
	}
}

func TestHTTPHandlerRequiresHostBoundaryAndPreservesBrowserSessionLogin(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	if _, err := NewHTTPHandler(HTTPConfig{Service: h.service}); err == nil {
		t.Fatal("handler exposed routes without a host boundary")
	}
	boundary := &fakeBoundary{}
	handler, err := NewHTTPHandler(HTTPConfig{Service: h.service, Boundary: boundary})
	if err != nil {
		t.Fatal(err)
	}
	account := h.accounts.seedPassword(t, "http@example.test", "http-user", true)
	body := `{"identifier":"http@example.test","password":"` + testPassword + `"}`
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"credential_type":"browser_session"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "access_token") {
		t.Fatal("browser response leaked desktop bearer")
	}
	if len(boundary.calls) != 1 || boundary.calls[0] != BoundaryLogin {
		t.Fatalf("boundary calls=%v", boundary.calls)
	}
	session, active, _ := h.sessions.CurrentBrowserSession(context.Background())
	if !active || session.Subject != account.ID {
		t.Fatal("login did not establish host browser session")
	}
}

func TestHTTPBoundaryDenialStopsLogin(t *testing.T) {
	h := newServiceHarness(t, VerificationDisabled, nil)
	h.accounts.seedPassword(t, "http@example.test", "http-user", true)
	boundary := &fakeBoundary{err: ErrRateLimited}
	handler, err := NewHTTPHandler(HTTPConfig{Service: h.service, Boundary: boundary})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"identifier":"http@example.test","password":"`+testPassword+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, active, _ := h.sessions.CurrentBrowserSession(context.Background()); active {
		t.Fatal("denied login created a session")
	}
}

func TestNewServiceSupportsFacebookAndRejectsUnknownProvider(t *testing.T) {
	accounts := newMemoryAccounts()
	config := ServiceConfig{Accounts: accounts, Policy: &memoryPolicy{mode: VerificationDisabled, accounts: accounts}, BrowserSessions: &memorySessions{}, BrowserSessionLifetime: func(context.Context, Account) (time.Duration, error) { return time.Hour, nil }}
	config.OAuthProviders = map[string]OAuthProvider{"facebook": &fakeProvider{name: "facebook"}}
	if _, err := NewService(config); err != nil {
		t.Fatalf("Facebook adapter rejected: %v", err)
	}
	config.OAuthProviders = map[string]OAuthProvider{"unknown": &fakeProvider{name: "unknown"}}
	if _, err := NewService(config); err == nil {
		t.Fatal("unknown provider was accepted")
	}
}

func TestProviderAuthorizationRedirectIsPinnedToKnownProviderHost(t *testing.T) {
	for provider, candidate := range map[string]string{
		"google":               "https://accounts.google.com/o/oauth2/v2/auth?state=s",
		"github":               "https://github.com/login/oauth/authorize?state=s",
		"apple":                "https://appleid.apple.com/auth/authorize?state=s",
		"facebook":             "https://www.facebook.com/v27.0/dialog/oauth?state=s",
		"google-open-redirect": "https://evil.test/o/oauth2/v2/auth?state=s",
	} {
		want := provider != "google-open-redirect"
		if got := validProviderAuthorizationURL(provider, candidate); got != want {
			t.Errorf("provider=%s got=%v want=%v", provider, got, want)
		}
	}
}

func TestHTTPRegisterReportsPostCommitVerificationDeliveryFailureWithoutSuggestingDuplicateSignup(t *testing.T) {
	h := newServiceHarness(t, VerificationOptional, nil)
	h.emails.err = errors.New("smtp unavailable")
	boundary := &fakeBoundary{}
	handler, err := NewHTTPHandler(HTTPConfig{Service: h.service, Boundary: boundary})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"email":"new@example.test","username":"new-user","password":"` + testPassword + `","confirmation":"` + testPassword + `","terms_accepted":true,"turnstile_token":"challenge-response"}`
	request := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"registered":true`) || !strings.Contains(response.Body.String(), "Request a new verification email") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "password_hash") || strings.Contains(response.Body.String(), "smtp unavailable") {
		t.Fatalf("response leaked internal account or mail details: %s", response.Body.String())
	}
	account, err := h.accounts.FindByEmail(context.Background(), "new@example.test")
	if err != nil || account.EmailVerified {
		t.Fatalf("account=%+v err=%v", account, err)
	}
	if _, active, err := h.sessions.CurrentBrowserSession(context.Background()); err != nil || !active {
		t.Fatalf("optional-mode signup should remain usable, active=%v err=%v", active, err)
	}
	if len(boundary.calls) != 1 || boundary.calls[0] != BoundaryRegister {
		t.Fatalf("boundary calls=%v", boundary.calls)
	}
}

func TestOAuthProviderRegistrationCarriesInviteAndTermsToHostOnly(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "google-invite-sub", Email: "verified@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	redirect := "https://nexss.example.test/auth/oauth/google/callback"
	attempt := RegistrationAttempt{Email: "spoof@example.test", Username: "spoof", InviteCode: "secret-one-time-invite", TermsAccepted: true}
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "google", redirect, false, attempt, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(authorizationURL, attempt.InviteCode) || strings.Contains(authorizationURL, attempt.Email) || strings.Contains(authorizationURL, attempt.Username) {
		t.Fatalf("host registration data leaked in authorization URL: %s", authorizationURL)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	pending, ok := h.oauthStates.items[TokenDigest(state)]
	if !ok || pending.Registration.InviteCode != attempt.InviteCode || !pending.Registration.TermsAccepted || pending.Registration.Email != "" || pending.Registration.Username != "" {
		t.Fatalf("pending host context=%+v present=%v", pending.Registration, ok)
	}
	if _, err := h.service.CompleteProviderLogin(context.Background(), "google", state, "code"); err != nil {
		t.Fatal(err)
	}
	if len(h.policy.provisionAttempts) != 1 {
		t.Fatalf("host received %d provider attempts", len(h.policy.provisionAttempts))
	}
	createdAttempt := h.policy.provisionAttempts[0]
	if createdAttempt.Email != "verified@example.test" || createdAttempt.InviteCode != attempt.InviteCode || !createdAttempt.TermsAccepted || createdAttempt.Username != "" {
		t.Fatalf("host provider attempt=%+v", createdAttempt)
	}
}

func TestHTTPProviderCallbackReturnsToHostAndPreservesRegistrationContext(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "browser-sub", Email: "browser@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	registration := RegistrationAttempt{InviteCode: "browser-invite", TermsAccepted: true}
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "google", "https://nexss.example.test/auth/oauth/google/callback", false, registration, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	var outcome OAuthCallbackOutcome
	handler, err := NewHTTPHandler(HTTPConfig{
		Service: h.service, Boundary: &fakeBoundary{},
		OAuthCallbackRedirector: func(_ context.Context, got OAuthCallbackOutcome) (string, error) {
			outcome = got
			return "/editor?login=google", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?state="+url.QueryEscape(parsed.Query().Get("state"))+"&code=provider-code", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/editor?login=google" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if outcome.Provider != "google" || outcome.AccountID == "" || outcome.Err != nil || outcome.Registration.InviteCode != registration.InviteCode || !outcome.Registration.TermsAccepted {
		t.Fatalf("callback outcome=%+v", outcome)
	}
	if !validHostCallbackRedirect("/login?error=oauth") || !validHostCallbackRedirect("https://editor.example.test/") || validHostCallbackRedirect("//evil.example.test/") || validHostCallbackRedirect("http://evil.example.test/") || validHostCallbackRedirect("javascript:alert(1)") {
		t.Fatal("host callback redirect validation did not reject unsafe destinations")
	}
}

func TestOAuthDesktopProviderCallbackRedirectsLoopbackAndIssuesSeparateBearer(t *testing.T) {
	provider := &fakeProvider{identity: ProviderIdentity{Provider: "google", Subject: "desktop-google", Email: "desktop-oauth@example.test", EmailVerified: true}}
	h := newServiceHarness(t, VerificationDisabled, provider)
	desktopState, err := NewStateToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := PKCEChallenge(verifier)
	loopback := "http://127.0.0.1:24567/callback"
	if err := h.service.StartDesktopAuth(context.Background(), desktopState, challenge, loopback); err != nil {
		t.Fatal(err)
	}
	registration := RegistrationAttempt{InviteCode: "desktop-invite", TermsAccepted: true}
	authorizationURL, err := h.service.BeginProviderLogin(context.Background(), "google", "https://nexss.example.test/auth/oauth/google/callback", false, registration, desktopState)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	handler, err := NewHTTPHandler(HTTPConfig{Service: h.service, Boundary: &fakeBoundary{}, OAuthCallbackRedirector: func(context.Context, OAuthCallbackOutcome) (string, error) {
		return "/must-not-replace-desktop-loopback", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	callback := "/auth/oauth/google/callback?state=" + url.QueryEscape(parsed.Query().Get("state")) + "&code=provider-code"
	request := httptest.NewRequest(http.MethodGet, callback, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	callbackURL, err := url.Parse(response.Header().Get("Location"))
	if err != nil || callbackURL.Scheme != "http" || callbackURL.Host != "127.0.0.1:24567" || callbackURL.Path != "/callback" || callbackURL.Query().Get("state") != desktopState || callbackURL.Query().Get("code") == "" {
		t.Fatalf("desktop callback URL=%s err=%v", response.Header().Get("Location"), err)
	}
	token, expires, err := h.service.ExchangeDesktopAuthCode(context.Background(), callbackURL.Query().Get("code"), verifier)
	if err != nil || len(token) != 43 || !expires.After(h.now) {
		t.Fatalf("desktop exchange token-len=%d expires=%s err=%v", len(token), expires, err)
	}
	bearer, ok, err := h.bearers.ResolveDesktopBearer(context.Background(), TokenDigest(token), h.now)
	if err != nil || !ok || bearer.Subject == "" {
		t.Fatalf("bearer=%+v ok=%v err=%v", bearer, ok, err)
	}
	if _, active, err := h.sessions.CurrentBrowserSession(context.Background()); err != nil || !active {
		t.Fatalf("provider callback should also establish the browser session, active=%v err=%v", active, err)
	}
	if err := h.service.StartBrowserSession(context.Background(), Account{}); err == nil {
		t.Fatal("empty browser identity unexpectedly succeeded")
	}
}
