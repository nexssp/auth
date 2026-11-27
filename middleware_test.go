package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nexssp/testkit"
)

func TestJWTMiddleware_PublicPathMatchingIsExplicit(t *testing.T) {
	protected := JWTMiddleware(JWTConfig{
		PublicPaths: []string{"/auth/login", "/auth/oauth/", "/public/"},
		VerifyFn: func(context.Context, string) (jwt.MapClaims, error) {
			return nil, errors.New("invalid token")
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, path := range []string{"/auth/login", "/auth/oauth/google/login", "/public/status"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		res := httptest.NewRecorder()
		protected.ServeHTTP(res, req)
		if res.Code != http.StatusNoContent {
			t.Fatalf("public path %q returned %d, want %d", path, res.Code, http.StatusNoContent)
		}
	}

	for _, path := range []string{"/auth/login-admin", "/auth/oauthish", "/publicity"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		res := httptest.NewRecorder()
		protected.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("lookalike protected path %q returned %d, want %d", path, res.Code, http.StatusUnauthorized)
		}
	}
}

func TestJWTMiddlewareDoesNotAcceptQueryToken(t *testing.T) {
	protected := JWTMiddleware(JWTConfig{
		VerifyFn: func(context.Context, string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": "user-1"}, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected?token=query-token", http.NoBody)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("query-string token returned status %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestJWTMiddlewareMissingVerifierFailsClosed(t *testing.T) {
	nextCalled := false
	handler := JWTMiddleware(JWTConfig{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	testkit.NewWithHandler(t, handler).
		GET("/private").
		WithBearerToken("opaque-token").
		Do().
		ExpectStatus(http.StatusServiceUnavailable)
	if nextCalled {
		t.Fatal("protected handler ran without a configured token verifier")
	}
}

func TestJWTMiddlewareBoundsRequestIDAndAcceptsCaseInsensitiveBearer(t *testing.T) {
	const expectedValue = "test-value"
	var verified string
	handler := JWTMiddleware(JWTConfig{
		VerifyFn: func(_ context.Context, got string) (jwt.MapClaims, error) {
			verified = got
			return jwt.MapClaims{"sub": "user-1"}, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	requestID := strings.Repeat("x", 129)
	response := testkit.NewWithHandler(t, handler).
		GET("/private").
		WithHeader("Authorization", "bEaReR "+expectedValue).
		WithHeader("X-Request-ID", requestID).
		Do().
		ExpectStatus(http.StatusNoContent)
	if verified != expectedValue {
		t.Fatalf("verified value = %q, want %q", verified, expectedValue)
	}
	if got := response.Header("X-Request-ID"); got == requestID || len(got) != 36 {
		t.Fatalf("response request ID = %q, want generated UUID instead of oversized input", got)
	}
}

func TestMFAOnlyCredentialsCannotAuthorizeProtectedRoutes(t *testing.T) {
	t.Setenv("AUTH_MFA_REQUIRED", "true")
	plugin, err := New(Config{Env: "test", MFAProviders: map[string]MFAProvider{"email": nil}})
	if err != nil {
		t.Fatal(err)
	}
	nextCalls := 0
	protected := plugin.Protect()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, test := range []struct {
		name      string
		tokenType string
		wantMFA   bool
		legacy    bool
	}{
		{name: "MFA pre-auth", tokenType: tokenTypeMFAPreAuth, wantMFA: true},
		{name: "trusted device", tokenType: tokenTypeTrustedDevice},
		{name: "legacy MFA pre-auth", tokenType: tokenTypeMFAPreAuth, wantMFA: true, legacy: true},
		{name: "legacy trusted device", tokenType: tokenTypeTrustedDevice, legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": "user-1", "type": test.tokenType, "exp": time.Now().Add(time.Minute).Unix(),
			}
			var access string
			if test.legacy {
				privateKey, _ := currentKeys()
				var err error
				access, err = jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				tokens, err := GenerateTokensWithClaims(claims)
				if err != nil {
					t.Fatal(err)
				}
				access = tokens.Access
			}
			if _, err := verifyTypedAccessToken(access, test.tokenType); err != nil {
				t.Fatalf("dedicated typed-token verifier rejected %q: %v", test.tokenType, err)
			}
			if got := plugin.requiresSecondFactor(access, "user-1"); got != test.wantMFA {
				t.Fatalf("requiresSecondFactor(%q)=%v, want %v", test.tokenType, got, test.wantMFA)
			}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/private", http.NoBody)
			request.Header.Set("Authorization", "Bearer "+access)
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("protected route accepted %q credential with status %d", test.tokenType, response.Code)
			}
		})
	}
	if nextCalls != 0 {
		t.Fatalf("protected handler ran %d times for MFA-only credentials", nextCalls)
	}
	ordinary, err := GenerateTokens("", "user-1", "user")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/private", http.NoBody)
	request.Header.Set("Authorization", "Bearer "+ordinary.Access)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || nextCalls != 1 {
		t.Fatalf("ordinary access token status=%d handler calls=%d, want 204 and one call", response.Code, nextCalls)
	}
}
