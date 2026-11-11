package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nexssp/auth"
	"github.com/nexssp/auth/nexssflow"
	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"
)

const sessionCookieName = "nexss_demo_session"

type requestContextKey struct{}

type requestState struct {
	writer  http.ResponseWriter
	request *http.Request
}

type grant struct {
	roles          []string
	permissions    []string
	organizationID string
}

// These local DTOs mirror the useful subset of InvoicerX's invoice.list action.
// The real application action and tenant-aware repository are not imported here.
type invoiceListRequest struct {
	Search     string `json:"search"`
	Year       string `json:"year"`
	TypeFilter string `json:"type_filter"`
	DateFrom   string `json:"date_from"`
	DateTo     string `json:"date_to"`
	Limit      int    `json:"limit"`
	Page       int    `json:"page"`
	Sort       string `json:"sort"`
}

type demoInvoice struct {
	ID            uint    `json:"id"`
	InvoiceNumber string  `json:"invoice_number"`
	InvoiceDate   string  `json:"invoice_date"`
	InvoiceType   string  `json:"invoice_type"`
	CustomerName  string  `json:"c_name"`
	Currency      string  `json:"currency"`
	Total         float64 `json:"total"`
}

type scopedDemoInvoice struct {
	organizationID string
	invoice        demoInvoice
}

type invoiceListResponse struct {
	Data  []demoInvoice `json:"data"`
	Total int           `json:"total"`
	Years []string      `json:"years"`
}

type memoryGrants struct {
	mu    sync.RWMutex
	items map[string]grant
}

func newMemoryGrants() *memoryGrants {
	return &memoryGrants{items: make(map[string]grant)}
}

func (store *memoryGrants) set(accountID string, value grant) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[accountID] = grant{
		roles:          append([]string(nil), value.roles...),
		permissions:    append([]string(nil), value.permissions...),
		organizationID: value.organizationID,
	}
}

func (store *memoryGrants) get(accountID string) grant {
	store.mu.RLock()
	defer store.mu.RUnlock()
	value := store.items[accountID]
	return grant{
		roles:          append([]string(nil), value.roles...),
		permissions:    append([]string(nil), value.permissions...),
		organizationID: value.organizationID,
	}
}

func listDemoInvoices(organizationID string, request invoiceListRequest, records []scopedDemoInvoice) invoiceListResponse {
	limit := request.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	page := request.Page
	if page <= 0 {
		page = 1
	}

	yearSet := make(map[string]struct{})
	matching := make([]demoInvoice, 0)
	for _, record := range records {
		if record.organizationID != organizationID {
			continue
		}
		invoice := record.invoice
		year := ""
		if len(invoice.InvoiceDate) >= 4 {
			year = invoice.InvoiceDate[:4]
			yearSet[year] = struct{}{}
		}
		if request.Year != "" && request.Year != "all" && year != request.Year {
			continue
		}
		if request.TypeFilter == "standard" && invoice.InvoiceType != "VAT" && invoice.InvoiceType != "ZW" && invoice.InvoiceType != "UPR" {
			continue
		}
		if request.DateFrom != "" && invoice.InvoiceDate < request.DateFrom {
			continue
		}
		if request.DateTo != "" && invoice.InvoiceDate > request.DateTo {
			continue
		}
		if request.Search != "" && !strings.Contains(strings.ToLower(invoice.InvoiceNumber+" "+invoice.CustomerName), strings.ToLower(request.Search)) {
			continue
		}
		matching = append(matching, invoice)
	}
	sort.SliceStable(matching, func(i, j int) bool {
		if request.Sort == "invoice_date" {
			return matching[i].InvoiceDate < matching[j].InvoiceDate
		}
		return matching[i].InvoiceDate > matching[j].InvoiceDate
	})
	years := make([]string, 0, len(yearSet))
	for year := range yearSet {
		years = append(years, year)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(years)))

	total := len(matching)
	start := (page - 1) * limit
	if start >= total {
		return invoiceListResponse{Data: []demoInvoice{}, Total: total, Years: years}
	}
	end := start + limit
	if end > total {
		end = total
	}
	return invoiceListResponse{Data: matching[start:end], Total: total, Years: years}
}

type memoryAccounts struct {
	mu         sync.RWMutex
	nextID     uint64
	byID       map[string]auth.Account
	byEmail    map[string]string
	byUsername map[string]string
	identities map[string]string
}

func newMemoryAccounts() *memoryAccounts {
	return &memoryAccounts{
		byID:       make(map[string]auth.Account),
		byEmail:    make(map[string]string),
		byUsername: make(map[string]string),
		identities: make(map[string]string),
	}
}

func (store *memoryAccounts) create(input auth.NewPasswordAccount) (auth.Account, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	email := strings.ToLower(strings.TrimSpace(input.Email))
	username := strings.TrimSpace(input.Username)
	if email == "" || username == "" || input.PasswordHash == "" {
		return auth.Account{}, auth.ErrInvalidInput
	}
	if store.byEmail[email] != "" || store.byUsername[username] != "" {
		return auth.Account{}, errors.New("demo account already exists")
	}
	store.nextID++
	id := strconv.FormatUint(store.nextID, 10)
	account := auth.Account{
		ID: id, Email: email, Username: username,
		PasswordHash: input.PasswordHash, EmailVerified: input.EmailVerified,
		AuthVersion: 1,
	}
	store.byID[id] = account
	store.byEmail[email] = id
	store.byUsername[username] = id
	return account, nil
}

func (store *memoryAccounts) FindByIdentifier(_ context.Context, identifier string) (auth.Account, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	id := store.byEmail[strings.ToLower(strings.TrimSpace(identifier))]
	if id == "" {
		id = store.byUsername[strings.TrimSpace(identifier)]
	}
	account, ok := store.byID[id]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return account, nil
}

func (store *memoryAccounts) FindByEmail(_ context.Context, email string) (auth.Account, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	id := store.byEmail[strings.ToLower(strings.TrimSpace(email))]
	account, ok := store.byID[id]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return account, nil
}

func (store *memoryAccounts) FindByID(_ context.Context, id string) (auth.Account, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	account, ok := store.byID[id]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return account, nil
}

func (store *memoryAccounts) UpdatePasswordAndRevokeAuth(_ context.Context, subject, passwordHash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, ok := store.byID[subject]
	if !ok {
		return auth.ErrAccountNotFound
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
		return auth.ErrAccountNotFound
	}
	account.EmailVerified = true
	store.byID[subject] = account
	return nil
}

func (store *memoryAccounts) FindByProviderIdentity(_ context.Context, provider, subject string) (auth.Account, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	id := store.identities[provider+"\x00"+subject]
	account, ok := store.byID[id]
	if !ok {
		return auth.Account{}, auth.ErrAccountNotFound
	}
	return account, nil
}

func (store *memoryAccounts) LinkProviderIdentity(_ context.Context, userID, provider, subject, _ string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.byID[userID]; !ok {
		return auth.ErrAccountNotFound
	}
	key := provider + "\x00" + subject
	if store.identities[key] != "" {
		return errors.New("demo provider identity already linked")
	}
	store.identities[key] = userID
	return nil
}

type demoPolicy struct {
	accounts *memoryAccounts
	grants   *memoryGrants
}

func (policy *demoPolicy) EmailVerificationMode(context.Context) (auth.EmailVerificationMode, error) {
	return auth.VerificationDisabled, nil
}

func (policy *demoPolicy) CreatePasswordAccount(_ context.Context, attempt auth.RegistrationAttempt, account auth.NewPasswordAccount) (auth.Account, error) {
	if !attempt.TermsAccepted {
		return auth.Account{}, errors.New("accept the demo terms to register")
	}
	created, err := policy.accounts.create(account)
	if err != nil {
		return auth.Account{}, err
	}
	// These fake roles, permissions, and workspace membership are app policy, not auth defaults.
	policy.grants.set(created.ID, grant{
		roles: []string{"analyst", "viewer"}, permissions: []string{"reports:read"},
		organizationID: "northwind-demo",
	})
	return created, nil
}

func (*demoPolicy) ProvisionProviderAccount(context.Context, auth.ProviderIdentity, auth.RegistrationAttempt) (auth.Account, error) {
	return auth.Account{}, errors.New("OAuth account provisioning is not part of this local demo")
}

type memoryBrowserSessions struct {
	mu       sync.RWMutex
	sessions map[string]auth.BrowserSession
}

func newMemoryBrowserSessions() *memoryBrowserSessions {
	return &memoryBrowserSessions{sessions: make(map[string]auth.BrowserSession)}
}

func stateFromContext(ctx context.Context) (requestState, bool) {
	state, ok := ctx.Value(requestContextKey{}).(requestState)
	return state, ok && state.writer != nil && state.request != nil
}

func (store *memoryBrowserSessions) EstablishBrowserSession(ctx context.Context, session auth.BrowserSession) error {
	state, ok := stateFromContext(ctx)
	if !ok {
		return errors.New("demo session host requires an HTTP request context")
	}
	token, err := auth.NewOpaqueToken()
	if err != nil {
		return err
	}
	store.mu.Lock()
	if cookie, err := state.request.Cookie(sessionCookieName); err == nil {
		delete(store.sessions, auth.TokenDigest(cookie.Value))
	}
	store.sessions[token.Digest] = session
	store.mu.Unlock()
	http.SetCookie(state.writer, &http.Cookie{
		Name: sessionCookieName, Value: token.Value, Path: "/", Expires: session.ExpiresAt,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (store *memoryBrowserSessions) CurrentBrowserSession(ctx context.Context) (auth.BrowserSession, bool, error) {
	state, ok := stateFromContext(ctx)
	if !ok {
		return auth.BrowserSession{}, false, nil
	}
	cookie, err := state.request.Cookie(sessionCookieName)
	if err != nil {
		return auth.BrowserSession{}, false, nil
	}
	store.mu.RLock()
	session, found := store.sessions[auth.TokenDigest(cookie.Value)]
	store.mu.RUnlock()
	if !found || !session.ExpiresAt.After(time.Now()) {
		return auth.BrowserSession{}, false, nil
	}
	return session, true, nil
}

func (store *memoryBrowserSessions) EndBrowserSession(ctx context.Context) error {
	state, ok := stateFromContext(ctx)
	if !ok {
		return errors.New("demo session host requires an HTTP request context")
	}
	if cookie, err := state.request.Cookie(sessionCookieName); err == nil {
		store.mu.Lock()
		delete(store.sessions, auth.TokenDigest(cookie.Value))
		store.mu.Unlock()
	}
	http.SetCookie(state.writer, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func authSessionIdentity(sessions *memoryBrowserSessions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx := auth.WithHTTPExchange(request.Context(), request, writer)
			session, authenticated, err := sessions.CurrentBrowserSession(ctx)
			if err != nil {
				writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "session lookup failed"})
				return
			}
			if authenticated {
				ctx = xctx.WithUserID(ctx, session.Subject)
			}
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func authSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Pragma", "no-cache")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

type loopbackBoundary struct{}

func (loopbackBoundary) AuthorizeAuthRequest(_ context.Context, _ auth.BoundaryOperation, request *http.Request, _ string) error {
	if request == nil || request.Method != http.MethodPost {
		return errors.New("the local demo accepts POST auth requests only")
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("the local demo requires JSON requests")
	}
	remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		remoteHost = request.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !remoteIP.IsLoopback() {
		return errors.New("the local demo is loopback-only")
	}
	if origin := request.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "http" || parsed.Host != request.Host {
			return errors.New("cross-origin auth requests are not allowed in the local demo")
		}
	}
	return nil
}

type loopbackFlowBoundary struct{}

func (loopbackFlowBoundary) AuthorizeAuthFlowAction(ctx context.Context, operation auth.BoundaryOperation, turnstileToken string) error {
	state, ok := stateFromContext(ctx)
	if !ok {
		return errors.New("the local demo requires a trusted HTTP request context")
	}
	return (loopbackBoundary{}).AuthorizeAuthRequest(ctx, operation, state.request, turnstileToken)
}

type localApp struct {
	accounts   *memoryAccounts
	grants     *memoryGrants
	sessions   *memoryBrowserSessions
	service    *auth.Service
	authBundle compiler.Bundle
	flowConfig runner.Config
	mux        *http.ServeMux
}

func newLocalApp() (*localApp, error) {
	accounts := newMemoryAccounts()
	grants := newMemoryGrants()
	sessions := newMemoryBrowserSessions()
	service, err := auth.NewService(auth.ServiceConfig{
		Accounts:        accounts,
		Policy:          &demoPolicy{accounts: accounts, grants: grants},
		BrowserSessions: sessions,
		BrowserSessionLifetime: func(context.Context, auth.Account) (time.Duration, error) {
			return 8 * time.Hour, nil
		},
	})
	if err != nil {
		return nil, err
	}
	authBundle := nexssflow.Bundle(nil)
	reportAction := action.New("reports.read", func(ctx context.Context, _ struct{}) (map[string]string, error) {
		userID := xctx.UserIDFrom(ctx)
		if userID == "" {
			return nil, errors.New("authenticated host context required")
		}
		return map[string]string{"report": "Demo report for account " + userID}, nil
	}).Build()
	demoInvoices := []scopedDemoInvoice{
		{organizationID: "northwind-demo", invoice: demoInvoice{
			ID: 101, InvoiceNumber: "FV/2026/001", InvoiceDate: "2026-04-03", InvoiceType: "VAT",
			CustomerName: "Northwind Components Sp. z o.o.", Currency: "PLN", Total: 1230.50,
		}},
		{organizationID: "northwind-demo", invoice: demoInvoice{
			ID: 102, InvoiceNumber: "KOR/2026/001", InvoiceDate: "2026-01-18", InvoiceType: "KOR",
			CustomerName: "Northwind Components Sp. z o.o.", Currency: "PLN", Total: 250.00,
		}},
		{organizationID: "southwind-demo", invoice: demoInvoice{
			ID: 201, InvoiceNumber: "FV/2026/999", InvoiceDate: "2026-05-07", InvoiceType: "VAT",
			CustomerName: "Southwind Trading Sp. z o.o.", Currency: "PLN", Total: 9900.00,
		}},
	}
	invoiceListAction := action.New("invoice.list", func(ctx context.Context, request invoiceListRequest) (invoiceListResponse, error) {
		userID := xctx.UserIDFrom(ctx)
		if userID == "" {
			return invoiceListResponse{}, errors.New("authenticated host context required")
		}
		membership := grants.get(userID)
		if !xctx.HasRole(ctx, "viewer") {
			return invoiceListResponse{}, errors.New("viewer role required")
		}
		if membership.organizationID == "" {
			return invoiceListResponse{}, errors.New("workspace membership required")
		}
		return listDemoInvoices(membership.organizationID, request, demoInvoices), nil
	}).Build()
	appBundle := compiler.Bundle{
		ID: "localapp_business",
		Libraries: []action.Library{
			{Name: "reports", Actions: []action.AnyAction{reportAction}},
			{Name: "invoice", Actions: []action.AnyAction{invoiceListAction}},
		},
	}
	bundles := append(native.Bundles(), authBundle, appBundle)
	flowConfig, err := runner.BuildConfig(bundles)
	if err != nil {
		return nil, err
	}
	httpAuth, err := auth.NewHTTPHandler(auth.HTTPConfig{Service: service, Boundary: loopbackBoundary{}})
	if err != nil {
		return nil, err
	}
	app := &localApp{
		accounts: accounts, grants: grants, sessions: sessions, service: service,
		authBundle: authBundle, flowConfig: flowConfig, mux: http.NewServeMux(),
	}
	app.mux.Handle("/auth/", authSessionIdentity(sessions)(httpAuth))
	currentSession := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result, err := auth.NewCurrentSessionAction(service).DoAny(request.Context(), auth.CurrentSessionRequest{})
		if err != nil {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
			return
		}
		writeJSON(writer, http.StatusOK, result)
	})
	app.mux.Handle("GET /auth/session", authSessionIdentity(sessions)(authSecurityHeaders(currentSession)))
	app.mux.HandleFunc("POST /flow/current-session", app.runFlow("examples/auth_full_lifecycle.nflow", map[string]any{
		"operation": "current_session", "credentials": map[string]any{},
	}))
	app.mux.HandleFunc("POST /flow/authorized-report", app.runFlow("nflows/authorized_report.nflow", nil))
	app.mux.HandleFunc("POST /flow/accountant-invoices", app.runFlow("nflows/accountant_invoices.nflow", nil))
	return app, nil
}

func (app *localApp) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := context.WithValue(request.Context(), requestContextKey{}, requestState{writer: writer, request: request})
	app.mux.ServeHTTP(writer, request.WithContext(ctx))
}

func (app *localApp) runFlow(sourcePath string, input map[string]any) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		account, authenticated, err := app.service.CurrentBrowserAccount(request.Context())
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "host session lookup failed"})
			return
		}
		if !authenticated {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}

		// Identity and authorization are injected from the validated host session and app-owned grants.
		trusted := xctx.WithUserID(request.Context(), account.ID)
		policy := app.grants.get(account.ID)
		trusted = xctx.WithRoles(trusted, policy.roles)
		trusted = xctx.WithPermissions(trusted, policy.permissions)
		trusted, err = nexssflow.WithRuntimeDependencies(trusted, app.service, loopbackFlowBoundary{})
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "host auth wiring is unavailable"})
			return
		}

		source, err := fs.ReadFile(app.authBundle.Fixtures, sourcePath)
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "Flow example is unavailable"})
			return
		}
		execution, err := runner.Execute(trusted, app.flowConfig, string(source), sourcePath, input)
		if err != nil {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "Flow authorization denied"})
			return
		}
		writeJSON(writer, http.StatusOK, execution.Output)
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		fmt.Printf("encode demo response: %v\n", err)
	}
}

func main() {
	app, err := newLocalApp()
	if err != nil {
		panic(err)
	}
	const address = "127.0.0.1:8085"
	fmt.Printf("Local auth/Flow demo listening at http://%s\n", address)
	fmt.Println("This loopback-only in-memory demo is not a production auth host.")
	if err := http.ListenAndServe(address, app); err != nil {
		panic(err)
	}
}
