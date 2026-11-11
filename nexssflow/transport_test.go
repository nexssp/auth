package nexssflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"
	transporthttp "github.com/nexssp/transport/thttp"
	thttpflow "github.com/nexssp/transport/thttp/nexssflow"

	"github.com/nexssp/auth"
)

func TestImportedAuthRoutesUseStandardTransportListener(t *testing.T) {
	bundle := Bundle(nil)
	bundle.Alias = "auth"

	sessions := &transportBrowserSessions{cookie: "transport-session"}
	service, accounts := newTransportFlowTestService(t, sessions)
	passwordHash, err := auth.HashPassword("transport-test-password")
	if err != nil {
		t.Fatal(err)
	}
	accounts.put(auth.Account{
		ID: "transport-account", Email: "transport@example.test", Username: "transport-user",
		PasswordHash: passwordHash, EmailVerified: true,
	})
	boundary := &transportFlowBoundary{}
	requestBoundary := &transportRequestBoundary{}
	httpHandler, err := auth.NewHTTPHandler(auth.HTTPConfig{Service: service, Boundary: requestBoundary})
	if err != nil {
		t.Fatal(err)
	}
	rawHandler := action.New("host.auth.oauth_begin", func(context.Context, struct{}) (struct{}, error) {
		return struct{}{}, nil
	}).Route(transporthttp.RawHandler(http.MethodPost, "/auth/oauth/{provider}/begin", httpHandler.ServeHTTP)).Build()
	rawBundle := compiler.Bundle{
		ID:        "host_auth_raw_routes",
		Libraries: []action.Library{{Name: "host_auth_raw_routes", Actions: []action.AnyAction{rawHandler}}},
	}
	config, err := runner.BuildConfig(append(native.Bundles(), bundle, rawBundle, thttpflow.Bundle(nil)))
	if err != nil {
		t.Fatal(err)
	}
	address := reserveAndReleaseTransportAddress(t)
	source := "@include auth:nflows/auth.nflow AS auth_api\nthttp.listen"

	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx := auth.WithHTTPExchange(request.Context(), request, writer)
			session, authenticated, err := sessions.CurrentBrowserSession(ctx)
			if err != nil {
				http.Error(writer, "session lookup failed", http.StatusInternalServerError)
				return
			}
			ctx, err = WithRuntimeDependencies(ctx, service, boundary)
			if err != nil {
				http.Error(writer, "auth runtime unavailable", http.StatusServiceUnavailable)
				return
			}
			if authenticated {
				ctx = xctx.WithUserID(ctx, session.Subject)
			}
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}

	listenerCtx := thttpflow.WithRuntimeConfig(context.Background(), thttpflow.RuntimeConfig{
		Addr: address, Middlewares: []func(http.Handler) http.Handler{middleware},
	})
	ctx, cancel := context.WithCancel(listenerCtx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, runErr := runner.Execute(ctx, config, source, "auth_transport_test.nflow", nil)
		done <- runErr
	}()

	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	defer client.CloseIdleConnections()
	endpoint := "http://" + address
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/auth/session", http.NoBody)
		if requestErr == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusUnauthorized {
					ready = true
					break
				}
			}
		}
		select {
		case runErr := <-done:
			t.Fatalf("Transport listener exited before serving HTTP: %v", runErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("standard Transport listener did not become ready")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/auth/login", strings.NewReader(`{"credentials":{"identifier":"transport@example.test","password":"transport-test-password"}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var login map[string]any
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || login["authenticated"] != true {
		t.Fatalf("standard Transport login status=%d body=%#v", response.StatusCode, login)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "flow_session" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("host BrowserSessionHost did not write its cookie to the real response: %#v", cookies)
	}

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/auth/session", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookies[0])
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var session map[string]any
	if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || session["account_id"] != "transport-account" {
		t.Fatalf("cookie-backed session route status=%d body=%#v", response.StatusCode, session)
	}

	request, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/auth/logout", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookies[0])
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("standard Transport logout status=%d", response.StatusCode)
	}
	cleared := response.Cookies()
	if len(cleared) != 1 || cleared[0].Name != cookies[0].Name || cleared[0].MaxAge >= 0 {
		t.Fatalf("host BrowserSessionHost did not clear its cookie on the real response: %#v", cleared)
	}

	if got, want := boundary.snapshot(), []string{"POST /auth/login", "POST /auth/logout"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Flow action boundary calls=%v, want %v", got, want)
	}

	request, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/auth/oauth/test-provider/begin", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		t.Fatal("host-registered OAuth RawHandler route was not served by standard Transport")
	}
	if got := requestBoundary.snapshot(); got != "POST /auth/oauth/test-provider/begin" {
		t.Fatalf("raw handler request boundary saw %q", got)
	}
	cancel()
	select {
	case runErr := <-done:
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Transport listener shutdown error: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("standard Transport listener did not stop after context cancellation")
	}
}

func reserveAndReleaseTransportAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func newTransportFlowTestService(t *testing.T, sessions auth.BrowserSessionHost) (*auth.Service, *flowTestAccounts) {
	t.Helper()
	accounts := &flowTestAccounts{byID: make(map[string]auth.Account), byEmail: make(map[string]string), byIdentifier: make(map[string]string)}
	policy := &flowTestPolicy{mode: auth.VerificationDisabled, accounts: accounts}
	service, err := auth.NewService(auth.ServiceConfig{
		Accounts: accounts, Policy: policy, BrowserSessions: sessions,
		BrowserSessionLifetime: func(context.Context, auth.Account) (time.Duration, error) { return time.Hour, nil },
		Emails:                 &flowTestEmails{},
		PasswordResetTokens:    auth.OneTimeTokens{Store: &flowTestTokenStore{tokens: make(map[string]flowTestToken)}},
		EmailVerifyTokens:      auth.OneTimeTokens{Store: &flowTestTokenStore{tokens: make(map[string]flowTestToken)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, accounts
}

type transportBrowserSessions struct {
	mu      sync.Mutex
	cookie  string
	session auth.BrowserSession
	active  bool
}

func (sessions *transportBrowserSessions) EstablishBrowserSession(ctx context.Context, session auth.BrowserSession) error {
	exchange, ok := auth.HTTPExchangeFromContext(ctx)
	if !ok || exchange.Request.Method != http.MethodPost || exchange.Response == nil {
		return errors.New("host HTTP exchange is unavailable")
	}
	sessions.mu.Lock()
	sessions.session, sessions.active = session, true
	sessions.mu.Unlock()
	http.SetCookie(exchange.Response, &http.Cookie{
		Name: "flow_session", Value: sessions.cookie, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (sessions *transportBrowserSessions) CurrentBrowserSession(ctx context.Context) (auth.BrowserSession, bool, error) {
	exchange, ok := auth.HTTPExchangeFromContext(ctx)
	if !ok {
		return auth.BrowserSession{}, false, nil
	}
	cookie, err := exchange.Request.Cookie("flow_session")
	if err != nil {
		return auth.BrowserSession{}, false, nil
	}
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	if !sessions.active || cookie.Value != sessions.cookie {
		return auth.BrowserSession{}, false, nil
	}
	return sessions.session, true, nil
}

func (sessions *transportBrowserSessions) EndBrowserSession(ctx context.Context) error {
	exchange, ok := auth.HTTPExchangeFromContext(ctx)
	if !ok || exchange.Request.Method != http.MethodPost || exchange.Response == nil {
		return errors.New("host HTTP exchange is unavailable")
	}
	sessions.mu.Lock()
	sessions.active = false
	sessions.mu.Unlock()
	http.SetCookie(exchange.Response, &http.Cookie{
		Name: "flow_session", Value: "", Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	return nil
}

type transportFlowBoundary struct {
	mu    sync.Mutex
	calls []string
}

func (boundary *transportFlowBoundary) AuthorizeAuthFlowAction(ctx context.Context, _ auth.BoundaryOperation, _ string) error {
	exchange, ok := auth.HTTPExchangeFromContext(ctx)
	if !ok || exchange.Request.URL.Path == "" {
		return errors.New("host HTTP exchange is unavailable at the Flow boundary")
	}
	boundary.mu.Lock()
	boundary.calls = append(boundary.calls, exchange.Request.Method+" "+exchange.Request.URL.Path)
	boundary.mu.Unlock()
	return nil
}

func (boundary *transportFlowBoundary) snapshot() []string {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return append([]string(nil), boundary.calls...)
}

type transportRequestBoundary struct {
	mu   sync.Mutex
	call string
}

func (boundary *transportRequestBoundary) AuthorizeAuthRequest(ctx context.Context, _ auth.BoundaryOperation, request *http.Request, _ string) error {
	exchange, ok := auth.HTTPExchangeFromContext(ctx)
	if !ok || exchange.Request.URL.Path != request.URL.Path {
		return errors.New("host HTTP exchange is unavailable at the raw request boundary")
	}
	boundary.mu.Lock()
	boundary.call = request.Method + " " + request.URL.Path
	boundary.mu.Unlock()
	return nil
}

func (boundary *transportRequestBoundary) snapshot() string {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return boundary.call
}
