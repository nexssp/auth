package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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
