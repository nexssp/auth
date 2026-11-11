package nexssflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"

	"github.com/nexssp/auth"
)

func TestNewBundleRequiresBoundaryForCredentialActions(t *testing.T) {
	service, _, _, _, _ := newFlowTestService(t, auth.VerificationOptional)
	if _, err := NewBundleWithBoundary(service, nil); err == nil {
		t.Fatal("NewBundleWithBoundary accepted a nil host boundary")
	}
	bundle := NewBundle(service)
	if len(bundle.Libraries) != 1 || len(bundle.Libraries[0].Actions) != 1 {
		t.Fatalf("session-only bundle mounted unexpected actions: %#v", bundle.Libraries)
	}
	if len(bundle.ExportedModules) != 0 {
		t.Fatalf("session-only bundle exported route modules: %v", bundle.ExportedModules)
	}
	if got := bundle.Libraries[0].Actions[0].Describe().Name; got != "auth.current_session" {
		t.Fatalf("session-only action = %q", got)
	}
}

func TestBundleFactoryFailsClosedWithoutHostRuntimeDependencies(t *testing.T) {
	bundle := Bundle(nil)
	config := buildFlowConfig(t, bundle)
	source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "must-not-appear-in-runtime-error"
	_, err = runner.Execute(context.Background(), config, string(source), "auth_full_lifecycle.nflow", map[string]any{
		"operation": "login",
		"credentials": map[string]any{
			"identifier": "private@example.test", "password": secret, "turnstile_token": secret,
		},
	})
	if err == nil {
		t.Fatal("Bundle factory accepted a credential action without host runtime dependencies")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("missing-dependency error disclosed runtime input: %v", err)
	}
}

func TestSingleFileRequireExampleRunsThroughBundleFactory(t *testing.T) {
	service, store, _, _, _ := newFlowTestService(t, auth.VerificationDisabled)
	passwordHash, err := auth.HashPassword("single-file-example-password")
	if err != nil {
		t.Fatal(err)
	}
	store.put(auth.Account{
		ID: "example-account", Email: "example@example.test", Username: "example-user",
		PasswordHash: passwordHash, EmailVerified: true,
	})
	ctx, err := WithRuntimeDependencies(context.Background(), service, &flowTestBoundary{})
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle(nil)
	config := buildFlowConfig(t, bundle)
	source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runner.Execute(ctx, config, string(source), "auth_full_lifecycle.nflow", map[string]any{
		"operation": "login",
		"credentials": map[string]any{
			"identifier": "example@example.test", "password": "single-file-example-password",
			"turnstile_token": "example-turnstile",
		},
	})
	if err != nil {
		t.Fatalf("single-file @require example: %v", err)
	}
	var response loginResponse
	decodeOutput(t, execution.Output, &response)
	if !response.Authenticated || response.CredentialType != "browser_session" {
		t.Fatalf("single-file example login output = %#v", response)
	}
}

func TestAuthPipelineRejectsInvalidEmailBeforeCallingBoundary(t *testing.T) {
	service, _, _, _, _ := newFlowTestService(t, auth.VerificationOptional)
	boundary := &flowTestBoundary{}
	ctx, err := WithRuntimeDependencies(context.Background(), service, boundary)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle(nil)
	config := buildFlowConfig(t, bundle)
	source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Execute(ctx, config, string(source), "auth_full_lifecycle.nflow", map[string]any{
		"operation":   "password_forgot",
		"credentials": map[string]any{"email": "not-an-email", "turnstile_token": "test-token"},
	})
	if err == nil {
		t.Fatal("password_forgot accepted an invalid email address")
	}
	if calls := boundary.calls(); len(calls) != 0 {
		t.Fatalf("auth boundary ran before Flow request validation: %#v", calls)
	}
}

func TestLifecycleExampleExecutesThroughFlowRunnerWithFakeHost(t *testing.T) {
	service, store, policy, sessions, mail := newFlowTestService(t, auth.VerificationOptional)
	boundary := &flowTestBoundary{}
	bundle := Bundle(nil)
	if err := compiler.ValidateBundle(bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.ID != BundleID || len(bundle.Libraries) != 1 || bundle.Libraries[0].Name != LibraryName || len(bundle.Libraries[0].Actions) != 8 {
		t.Fatalf("bundle registration = %#v", bundle)
	}
	wantActions := []string{
		"auth.current_session", "auth.register", "auth.login", "auth.logout",
		"auth.password_forgot", "auth.password_reset", "auth.email_verify", "auth.email_resend",
	}
	gotActions := make(map[string]bool, len(bundle.Libraries[0].Actions))
	for _, mounted := range bundle.Libraries[0].Actions {
		gotActions[mounted.Describe().Name] = true
		if _, ok := mounted.(action.TypedPayload); !ok {
			t.Errorf("action %q has no typed payload: %T", mounted.Describe().Name, mounted)
		}
	}
	for _, name := range wantActions {
		if !gotActions[name] {
			t.Errorf("action %q was not mounted", name)
		}
	}

	config := buildFlowConfig(t, bundle)
	ctx, err := WithRuntimeDependencies(context.Background(), service, boundary)
	if err != nil {
		t.Fatal(err)
	}
	const password = "flow-test-password-not-for-production"
	registerInput := map[string]any{
		"email": "flow-user@example.test", "username": "flow-user",
		"password": password, "confirmation": password,
		"invite_code": "flow-test-invite", "terms_accepted": true,
		"turnstile_token": "flow-test-turnstile",
	}
	register := executeLifecycle(t, config, "register", ctx, registerInput)
	var registered registerResponse
	decodeOutput(t, register.Output, &registered)
	if !registered.Registered || !registered.Authenticated || registered.EmailVerification != auth.VerificationOptional {
		t.Fatalf("register output = %#v", registered)
	}
	assertOutputOmits(t, register.Output, password, "flow-user@example.test", "flow-test-invite", "flow-test-turnstile")
	account, ok := store.findByEmailValue("flow-user@example.test")
	if !ok || account.PasswordHash == password || account.EmailVerified {
		t.Fatalf("host policy did not persist expected initial account: %#v, exists=%v", account, ok)
	}
	policy.mu.Lock()
	attempt := policy.lastAttempt
	policy.mu.Unlock()
	if attempt.Email != "flow-user@example.test" || attempt.InviteCode != "flow-test-invite" || !attempt.TermsAccepted {
		t.Fatalf("registration policy did not receive host-owned fields: %#v", attempt)
	}
	if _, active, err := sessions.CurrentBrowserSession(ctx); err != nil || !active {
		t.Fatal("optional-verification registration did not establish a host session")
	}
	verificationToken := mail.lastToken(auth.EmailVerifyAddress)
	if verificationToken == "" {
		t.Fatal("registration did not send a verification email through the fake sender")
	}

	loginInput := map[string]any{
		"identifier": "flow-user@example.test", "password": password,
		"turnstile_token": "flow-login-turnstile",
	}
	login := executeLifecycle(t, config, "login", ctx, loginInput)
	var loggedIn loginResponse
	decodeOutput(t, login.Output, &loggedIn)
	if !loggedIn.Authenticated || loggedIn.CredentialType != "browser_session" {
		t.Fatalf("login output = %#v", loggedIn)
	}
	assertOutputOmits(t, login.Output, password, "flow-user@example.test", "flow-login-turnstile")

	current := executeLifecycle(t, config, "current_session", xctx.WithUserID(ctx, account.ID), nil)
	var currentOutput auth.CurrentSessionResponse
	decodeOutput(t, current.Output, &currentOutput)
	if currentOutput.AccountID != account.ID || currentOutput.EmailVerified {
		t.Fatalf("current session output = %#v", currentOutput)
	}

	resend := executeLifecycle(t, config, "email_resend", ctx, map[string]any{
		"email": "flow-user@example.test", "turnstile_token": "flow-resend-turnstile",
	})
	var resent emailResendResponse
	decodeOutput(t, resend.Output, &resent)
	if resent.Message != "If verification is available for that address, an email will be sent." {
		t.Fatalf("email resend output = %#v", resent)
	}
	assertOutputOmits(t, resend.Output, "flow-user@example.test", "flow-resend-turnstile")

	verified := executeLifecycle(t, config, "email_verify", ctx, map[string]any{
		"token": verificationToken, "turnstile_token": "flow-verify-turnstile",
	})
	var verifyOutput emailVerifyResponse
	decodeOutput(t, verified.Output, &verifyOutput)
	if !verifyOutput.EmailVerified {
		t.Fatalf("email verify output = %#v", verifyOutput)
	}
	assertOutputOmits(t, verified.Output, verificationToken, "flow-verify-turnstile")
	account, ok = store.findByEmailValue("flow-user@example.test")
	if !ok || !account.EmailVerified {
		t.Fatal("host account store did not mark email verified")
	}

	forgot := executeLifecycle(t, config, "password_forgot", ctx, map[string]any{
		"email": "flow-user@example.test", "turnstile_token": "flow-forgot-turnstile",
	})
	var forgotOutput passwordForgotResponse
	decodeOutput(t, forgot.Output, &forgotOutput)
	if forgotOutput.Message != "If an account matches that email, a reset link will be sent." {
		t.Fatalf("password forgot output = %#v", forgotOutput)
	}
	assertOutputOmits(t, forgot.Output, "flow-user@example.test", "flow-forgot-turnstile")
	resetToken := mail.lastToken(auth.EmailPasswordReset)
	if resetToken == "" {
		t.Fatal("forgot-password did not send through the fake sender")
	}
	const replacementPassword = "flow-test-replacement-password"
	reset := executeLifecycle(t, config, "password_reset", ctx, map[string]any{
		"token": resetToken, "password": replacementPassword, "confirmation": replacementPassword,
	})
	var resetOutput passwordResetResponse
	decodeOutput(t, reset.Output, &resetOutput)
	if !resetOutput.PasswordChanged {
		t.Fatalf("password reset output = %#v", resetOutput)
	}
	assertOutputOmits(t, reset.Output, resetToken, replacementPassword)
	if updates := store.passwordUpdateCount(); updates != 1 {
		t.Fatalf("host password update/revocation calls = %d, want 1", updates)
	}

	logout := executeLifecycle(t, config, "logout", ctx, nil)
	var logoutOutput logoutResponse
	decodeOutput(t, logout.Output, &logoutOutput)
	if logoutOutput.Authenticated {
		t.Fatalf("logout output = %#v", logoutOutput)
	}
	if _, active, err := sessions.CurrentBrowserSession(ctx); err != nil || active {
		t.Fatal("logout did not end the host browser session")
	}

	wantCalls := []flowBoundaryCall{
		{operation: auth.BoundaryRegister, token: "flow-test-turnstile"},
		{operation: auth.BoundaryLogin, token: "flow-login-turnstile"},
		{operation: auth.BoundaryEmailVerify, token: "flow-resend-turnstile"},
		{operation: auth.BoundaryEmailVerify, token: "flow-verify-turnstile"},
		{operation: auth.BoundaryPasswordReset, token: "flow-forgot-turnstile"},
		{operation: auth.BoundaryPasswordReset},
		{operation: auth.BoundaryLogout},
	}
	gotCalls := boundary.calls()
	if len(gotCalls) != len(wantCalls) {
		t.Fatalf("host boundary calls = %#v, want %#v", gotCalls, wantCalls)
	}
	for i := range wantCalls {
		if gotCalls[i] != wantCalls[i] {
			t.Fatalf("host boundary call %d = %#v, want %#v", i, gotCalls[i], wantCalls[i])
		}
	}
	if source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow"); err != nil || len(source) == 0 {
		t.Fatalf("full lifecycle example missing or empty: err=%v", err)
	}
}

func TestNFlowSourcesContainNoCredentialLiterals(t *testing.T) {
	sources := []string{
		"examples/auth_full_lifecycle.nflow",
		"examples/flow_rest_api.nflow",
		"nflows/auth.nflow",
		"nflows/authorized_report.nflow",
		"nflows/accountant_invoices.nflow",
	}
	literalCredential := regexp.MustCompile(`(?i)\b(password|confirmation|token|invite_code|turnstile_token|access_token|authorization_code)\s*:\s*["'][^"']+["']`)
	for _, path := range sources {
		t.Run(path, func(t *testing.T) {
			source, err := fs.ReadFile(fixtures, path)
			if err != nil {
				t.Fatal(err)
			}
			if literalCredential.Match(source) {
				t.Fatalf("Flow source contains a literal credential value: %s", source)
			}
			for _, testValue := range []string{"flow-test-password-not-for-production", "flow-test-invite", "flow-test-turnstile"} {
				if strings.Contains(string(source), testValue) {
					t.Fatalf("Flow source contains runtime test value %q", testValue)
				}
			}
		})
	}
}

func TestFlowRunnerTraceRedactsRuntimeAuthInput(t *testing.T) {
	service, store, _, _, _ := newFlowTestService(t, auth.VerificationDisabled)
	passwordHash, err := auth.HashPassword("trace-test-correct-password")
	if err != nil {
		t.Fatal(err)
	}
	store.put(auth.Account{
		ID: "trace-account", Email: "trace-user@example.test", Username: "trace-user",
		PasswordHash: passwordHash, EmailVerified: true,
	})
	bundle, err := NewBundleWithBoundary(service, &flowTestBoundary{})
	if err != nil {
		t.Fatal(err)
	}
	config := buildFlowConfig(t, bundle)
	const runtimePassword = "trace-test-runtime-password-value"
	payload := map[string]any{
		"operation": "login",
		"credentials": map[string]any{
			"identifier": "trace-user@example.test", "password": "trace-test-correct-password",
			"turnstile_token": runtimePassword,
		},
	}
	source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runner.RunSource(context.Background(), config, string(source), "auth_full_lifecycle.nflow", payload, runner.Opts{
		Verbosity: 3,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if code != 0 {
		t.Fatalf("RunSource code=%d, stdout=%s, stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, secret := range []string{"trace-user@example.test", "trace-test-correct-password", runtimePassword} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatalf("Flow trace exposed runtime input %q:\n%s\n%s", secret, stdout.String(), stderr.String())
		}
	}
	if !strings.Contains(stdout.String(), "[REDACTED]") {
		t.Fatalf("verbose trace did not demonstrate redaction:\n%s", stdout.String())
	}
}

func TestBoundaryFailureDoesNotEchoRuntimeCredentials(t *testing.T) {
	service, _, _, _, _ := newFlowTestService(t, auth.VerificationDisabled)
	const secret = "boundary-error-runtime-secret"
	boundary := &flowTestBoundary{reject: errors.New("host policy rejected request containing " + secret)}
	bundle, err := NewBundleWithBoundary(service, boundary)
	if err != nil {
		t.Fatal(err)
	}
	config := buildFlowConfig(t, bundle)
	source, err := fs.ReadFile(bundle.Fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Execute(context.Background(), config, string(source), "auth_full_lifecycle.nflow", map[string]any{
		"operation": "login",
		"credentials": map[string]any{
			"identifier": "private@example.test", "password": secret, "turnstile_token": secret,
		},
	})
	if err == nil {
		t.Fatal("expected the fake host boundary to reject the login")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "host policy rejected") {
		t.Fatalf("Flow action leaked the host-boundary error: %v", err)
	}
}

func TestSensitiveInputRedactsJSONFormattingAndSlog(t *testing.T) {
	secret := sensitiveInput("not-for-logs")
	encoded, err := json.Marshal(struct {
		Password sensitiveInput `json:"password"`
	}{Password: secret})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(secret)) || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("JSON representation = %s", encoded)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", secret), fmt.Sprintf("%#v", secret), fmt.Sprintf("%s", secret)} {
		if strings.Contains(formatted, string(secret)) || formatted != "[REDACTED]" {
			t.Fatalf("formatted sensitive input = %q", formatted)
		}
	}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("auth request", "password", secret)
	if strings.Contains(logs.String(), string(secret)) || !strings.Contains(logs.String(), "[REDACTED]") {
		t.Fatalf("slog output = %s", logs.String())
	}
}

func buildFlowConfig(t *testing.T, bundle compiler.Bundle) runner.Config {
	t.Helper()
	config, err := runner.BuildConfig(append(native.Bundles(), bundle))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func executeLifecycle(t *testing.T, config runner.Config, filename string, ctx context.Context, input map[string]any) runner.Execution {
	t.Helper()
	source, err := fs.ReadFile(fixtures, "examples/auth_full_lifecycle.nflow")
	if err != nil {
		t.Fatal(err)
	}
	if input == nil {
		input = map[string]any{}
	}
	request := map[string]any{
		"operation":   strings.TrimSuffix(filename, ".nflow"),
		"credentials": input,
	}
	execution, err := runner.Execute(ctx, config, string(source), "auth_full_lifecycle.nflow", request)
	if err != nil {
		t.Fatalf("runner.Execute(%s): %v", filename, err)
	}
	return execution
}

func decodeOutput(t *testing.T, output, target any) {
	t.Helper()
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatalf("decode output %s: %v", encoded, err)
	}
}

func assertOutputOmits(t *testing.T, output any, values ...string) {
	t.Helper()
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value != "" && strings.Contains(string(encoded), value) {
			t.Errorf("Flow action output disclosed runtime value %q: %s", value, encoded)
		}
	}
}

func newFlowTestService(t *testing.T, mode auth.EmailVerificationMode) (*auth.Service, *flowTestAccounts, *flowTestPolicy, *flowTestSessions, *flowTestEmails) {
	t.Helper()
	accounts := &flowTestAccounts{byID: make(map[string]auth.Account), byEmail: make(map[string]string), byIdentifier: make(map[string]string)}
	policy := &flowTestPolicy{mode: mode, accounts: accounts}
	sessions := &flowTestSessions{}
	emails := &flowTestEmails{}
	service, err := auth.NewService(auth.ServiceConfig{
		Accounts:               accounts,
		Policy:                 policy,
		BrowserSessions:        sessions,
		BrowserSessionLifetime: func(context.Context, auth.Account) (time.Duration, error) { return time.Hour, nil },
		Emails:                 emails,
		PasswordResetTokens:    auth.OneTimeTokens{Store: &flowTestTokenStore{tokens: make(map[string]flowTestToken)}},
		EmailVerifyTokens:      auth.OneTimeTokens{Store: &flowTestTokenStore{tokens: make(map[string]flowTestToken)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, accounts, policy, sessions, emails
}

type flowTestAccounts struct {
	mu              sync.Mutex
	byID            map[string]auth.Account
	byEmail         map[string]string
	byIdentifier    map[string]string
	passwordUpdates int
}

func (store *flowTestAccounts) put(account auth.Account) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.byID[account.ID] = account
	store.byEmail[strings.ToLower(account.Email)] = account.ID
	store.byIdentifier[strings.ToLower(account.Email)] = account.ID
	store.byIdentifier[strings.ToLower(account.Username)] = account.ID
}

func (store *flowTestAccounts) findByEmailValue(email string) (auth.Account, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, ok := store.byEmail[strings.ToLower(email)]
	return store.byID[id], ok
}

func (store *flowTestAccounts) FindByIdentifier(_ context.Context, identifier string) (auth.Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, ok := store.byIdentifier[strings.ToLower(identifier)]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return store.byID[id], nil
}

func (store *flowTestAccounts) FindByEmail(_ context.Context, email string) (auth.Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, ok := store.byEmail[strings.ToLower(email)]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return store.byID[id], nil
}

func (store *flowTestAccounts) FindByID(_ context.Context, id string) (auth.Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[id]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return account, nil
}

func (store *flowTestAccounts) UpdatePasswordAndRevokeAuth(_ context.Context, id, passwordHash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[id]
	if !ok {
		return auth.ErrAccountNotFound
	}
	account.PasswordHash = passwordHash
	account.AuthVersion++
	store.byID[id] = account
	store.passwordUpdates++
	return nil
}

func (store *flowTestAccounts) MarkEmailVerified(_ context.Context, id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[id]
	if !ok {
		return auth.ErrAccountNotFound
	}
	account.EmailVerified = true
	store.byID[id] = account
	return nil
}

func (*flowTestAccounts) FindByProviderIdentity(context.Context, string, string) (auth.Account, error) {
	return auth.Account{}, auth.ErrAccountNotFound
}

func (*flowTestAccounts) LinkProviderIdentity(context.Context, string, string, string, string) error {
	return errors.New("not used")
}

func (store *flowTestAccounts) passwordUpdateCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.passwordUpdates
}

type flowTestPolicy struct {
	mode        auth.EmailVerificationMode
	accounts    *flowTestAccounts
	mu          sync.Mutex
	lastAttempt auth.RegistrationAttempt
}

func (policy *flowTestPolicy) EmailVerificationMode(context.Context) (auth.EmailVerificationMode, error) {
	return policy.mode, nil
}

func (policy *flowTestPolicy) CreatePasswordAccount(_ context.Context, attempt auth.RegistrationAttempt, input auth.NewPasswordAccount) (auth.Account, error) {
	policy.mu.Lock()
	policy.lastAttempt = attempt
	policy.mu.Unlock()
	account := auth.Account{
		ID: "account-flow-test", Email: input.Email, Username: input.Username,
		PasswordHash: input.PasswordHash, EmailVerified: input.EmailVerified,
	}
	policy.accounts.put(account)
	return account, nil
}

func (*flowTestPolicy) ProvisionProviderAccount(context.Context, auth.ProviderIdentity, auth.RegistrationAttempt) (auth.Account, error) {
	return auth.Account{}, errors.New("not used")
}

type flowTestSessions struct {
	mu      sync.Mutex
	session auth.BrowserSession
	active  bool
}

func (sessions *flowTestSessions) EstablishBrowserSession(_ context.Context, session auth.BrowserSession) error {
	sessions.mu.Lock()
	sessions.session = session
	sessions.active = true
	sessions.mu.Unlock()
	return nil
}

func (sessions *flowTestSessions) CurrentBrowserSession(context.Context) (auth.BrowserSession, bool, error) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	return sessions.session, sessions.active, nil
}

func (sessions *flowTestSessions) EndBrowserSession(context.Context) error {
	sessions.mu.Lock()
	sessions.active = false
	sessions.mu.Unlock()
	return nil
}

type flowTestBoundary struct {
	mu        sync.Mutex
	callsList []flowBoundaryCall
	reject    error
}

type flowBoundaryCall struct {
	operation auth.BoundaryOperation
	token     string
}

func (boundary *flowTestBoundary) AuthorizeAuthFlowAction(ctx context.Context, operation auth.BoundaryOperation, turnstileToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boundary.mu.Lock()
	boundary.callsList = append(boundary.callsList, flowBoundaryCall{operation: operation, token: turnstileToken})
	reject := boundary.reject
	boundary.mu.Unlock()
	return reject
}

func (boundary *flowTestBoundary) calls() []flowBoundaryCall {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return append([]flowBoundaryCall(nil), boundary.callsList...)
}

type flowTestEmails struct {
	mu       sync.Mutex
	messages []auth.AuthEmail
}

func (emails *flowTestEmails) SendAuthEmail(_ context.Context, message auth.AuthEmail) error {
	emails.mu.Lock()
	emails.messages = append(emails.messages, message)
	emails.mu.Unlock()
	return nil
}

func (emails *flowTestEmails) lastToken(kind string) string {
	emails.mu.Lock()
	defer emails.mu.Unlock()
	for i := len(emails.messages) - 1; i >= 0; i-- {
		if emails.messages[i].Kind == kind {
			return emails.messages[i].Token
		}
	}
	return ""
}

type flowTestToken struct {
	subject string
	expires time.Time
}

type flowTestTokenStore struct {
	mu     sync.Mutex
	tokens map[string]flowTestToken
}

func (store *flowTestTokenStore) InsertOneTimeToken(_ context.Context, digest, subject string, expires time.Time) error {
	store.mu.Lock()
	store.tokens[digest] = flowTestToken{subject: subject, expires: expires}
	store.mu.Unlock()
	return nil
}

func (store *flowTestTokenStore) ConsumeOneTimeToken(ctx context.Context, digest string, now time.Time, apply func(context.Context, string) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	token, ok := store.tokens[digest]
	if !ok || !token.expires.After(now) {
		return auth.ErrInvalidOneTimeToken
	}
	if err := apply(ctx, token.subject); err != nil {
		return err
	}
	delete(store.tokens, digest)
	return nil
}

func (store *flowTestTokenStore) RevokeOneTimeToken(_ context.Context, digest string) error {
	store.mu.Lock()
	delete(store.tokens, digest)
	store.mu.Unlock()
	return nil
}
