package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nexssp/testkit"
)

type turnstileVerifierFunc func(context.Context, string, string) error

func (verify turnstileVerifierFunc) Verify(ctx context.Context, responseToken, expectedAction string) error {
	return verify(ctx, responseToken, expectedAction)
}

type requestBoundaryFunc func(context.Context, BoundaryOperation, *http.Request, string) error

func (authorize requestBoundaryFunc) AuthorizeAuthRequest(ctx context.Context, operation BoundaryOperation, request *http.Request, token string) error {
	return authorize(ctx, operation, request, token)
}

type siteverifyRequestTransport struct {
	target *url.URL
	next   http.RoundTripper
}

func (transport siteverifyRequestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "challenges.cloudflare.com" || request.URL.Path != "/turnstile/v0/siteverify" {
		return nil, errors.New("unexpected Siteverify endpoint")
	}
	rewritten := request.Clone(request.Context())
	target := *request.URL
	target.Scheme = transport.target.Scheme
	target.Host = transport.target.Host
	rewritten.URL = &target
	rewritten.Host = transport.target.Host
	return transport.next.RoundTrip(rewritten)
}

func configureTestSiteverify(t *testing.T, handler http.Handler) *CloudflareTurnstileVerifier {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCloudflareTurnstileVerifier(CloudflareTurnstileConfig{
		SecretKey:        "test-secret-not-for-production",
		ExpectedHostname: "auth.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier.client.Transport = siteverifyRequestTransport{target: target, next: http.DefaultTransport}
	return verifier
}

func TestCloudflareTurnstileVerifierPostsAndBindsSuccess(t *testing.T) {
	const secret, token = "test-secret-not-for-production", "single-use-test-response"
	var received struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
	}
	verifier := configureTestSiteverify(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Siteverify method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Siteverify Content-Type = %q, want application/json", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode Siteverify request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.Contains(r.URL.String(), secret) || strings.Contains(r.URL.String(), token) {
			t.Error("secret or response token was placed in the URL")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"success": true, "hostname": "AUTH.EXAMPLE.COM.", "action": "login",
		}); err != nil {
			t.Errorf("write Siteverify response: %v", err)
		}
	}))

	if err := verifier.Verify(context.Background(), token, "login"); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if received.Secret != secret || received.Response != token {
		t.Fatalf("Siteverify payload = %#v", received)
	}
}

func TestCloudflareTurnstileVerifierFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{
			name:   "invalid response",
			status: http.StatusOK,
			body:   `{"success":false,"error-codes":["invalid-input-response"]}`,
			want:   ErrTurnstileRejected,
		},
		{
			name:   "provider configuration failure",
			status: http.StatusOK,
			body:   `{"success":false,"error-codes":["invalid-input-secret"]}`,
			want:   ErrTurnstileUnavailable,
		},
		{
			name:   "hostname mismatch",
			status: http.StatusOK,
			body:   `{"success":true,"hostname":"attacker.example","action":"login"}`,
			want:   ErrTurnstileRejected,
		},
		{
			name:   "action mismatch",
			status: http.StatusOK,
			body:   `{"success":true,"hostname":"auth.example.com","action":"register"}`,
			want:   ErrTurnstileRejected,
		},
		{
			name:   "provider failure",
			status: http.StatusBadGateway,
			body:   `{"success":true}`,
			want:   ErrTurnstileUnavailable,
		},
		{
			name:   "malformed provider response",
			status: http.StatusOK,
			body:   `{not-json`,
			want:   ErrTurnstileUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := configureTestSiteverify(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				if _, err := w.Write([]byte(test.body)); err != nil {
					t.Errorf("write Siteverify response: %v", err)
				}
			}))
			err := verifier.Verify(context.Background(), "private-token-value", "login")
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify error = %v, want %v", err, test.want)
			}
			if err != nil && (strings.Contains(err.Error(), "private-token-value") || strings.Contains(err.Error(), "test-secret-not-for-production")) {
				t.Fatalf("Verify error disclosed credential material: %v", err)
			}
		})
	}
}

func TestCloudflareTurnstileVerifierRejectsInvalidConfigurationAndInput(t *testing.T) {
	for _, config := range []CloudflareTurnstileConfig{
		{ExpectedHostname: "auth.example.com"},
		{SecretKey: "secret", ExpectedHostname: "https://auth.example.com"},
	} {
		if _, err := NewCloudflareTurnstileVerifier(config); !errors.Is(err, ErrTurnstileConfiguration) {
			t.Fatalf("constructor error = %v, want ErrTurnstileConfiguration", err)
		}
	}
	verifier, err := NewCloudflareTurnstileVerifier(CloudflareTurnstileConfig{
		SecretKey: "test-secret", ExpectedHostname: "auth.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), "", "login"); !errors.Is(err, ErrTurnstileRejected) {
		t.Fatalf("empty token error = %v, want ErrTurnstileRejected", err)
	}
	if err := verifier.Verify(context.Background(), "token", "invalid action"); !errors.Is(err, ErrTurnstileConfiguration) {
		t.Fatalf("invalid action error = %v, want ErrTurnstileConfiguration", err)
	}
}

func TestNewSecureHTTPHandlerRequiresAndVerifiesTurnstile(t *testing.T) {
	harness := newServiceHarness(t, VerificationDisabled, nil)
	var verifiedToken, verifiedAction string
	verifier := turnstileVerifierFunc(func(_ context.Context, token, action string) error {
		verifiedToken, verifiedAction = token, action
		return nil
	})
	hostBoundary := requestBoundaryFunc(func(context.Context, BoundaryOperation, *http.Request, string) error {
		return nil
	})
	handler, err := NewSecureHTTPHandler(HTTPConfig{Service: harness.service, Boundary: hostBoundary}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	suite := testkit.NewWithHandler(t, handler)
	login := map[string]string{
		"identifier": "unknown@example.test", "password": testPassword, "turnstile_token": "challenge-response",
	}
	suite.POST("/auth/login", login).Do().ExpectUnauthorized()
	if verifiedToken != "challenge-response" || verifiedAction != "login" {
		t.Fatalf("verified token/action = %q/%q", verifiedToken, verifiedAction)
	}

	delete(login, "turnstile_token")
	suite.POST("/auth/login", login).Do().ExpectForbidden()
	if verifiedToken != "challenge-response" {
		t.Fatalf("missing token reached verifier: %q", verifiedToken)
	}
}

func TestValidateTurnstileOperations(t *testing.T) {
	if err := ValidateTurnstileOperations(DefaultTurnstileOperations()...); err != nil {
		t.Fatalf("default operations rejected: %v", err)
	}
	if err := ValidateTurnstileOperations(BoundaryOAuthCallback); !errors.Is(err, ErrTurnstileConfiguration) {
		t.Fatalf("unsupported operation error = %v", err)
	}
}
