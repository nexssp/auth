// Replace the top part of auth/middleware.go with this:
package auth

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/nexssp/kernel/xctx"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTConfig struct {
	// Added context.Context to the signature!
	VerifyFn     func(ctx context.Context, token string) (jwt.MapClaims, error)
	TokenSource  func(r *http.Request) string
	ClaimsMapper func(scope *xctx.RequestScope, claims jwt.MapClaims)
	Optional     bool
	PublicPaths  []string
}

func JWTMiddleware(cfg JWTConfig) func(http.Handler) http.Handler {
	if cfg.TokenSource == nil {
		cfg.TokenSource = bearerToken
	}
	if cfg.ClaimsMapper == nil {
		cfg.ClaimsMapper = func(scope *xctx.RequestScope, claims jwt.MapClaims) {
			xctx.FromClaims(scope, map[string]any(claims))
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			cleanPath := path.Clean(r.URL.Path)
			isPublic := false
			for _, configuredPath := range cfg.PublicPaths {
				if matchesPublicPath(cleanPath, configuredPath) {
					isPublic = true
					break
				}
			}

			scope := xctx.ScopeFrom(ctx)
			var release func()
			if scope == nil {
				ctx, scope, release = xctx.NewScope(ctx)
				defer release()
			}

			if scope.RequestID == "" {
				reqID := r.Header.Get("X-Request-ID")
				if reqID == "" {
					reqID = uuid.NewString()
				}
				scope.RequestID = reqID
				w.Header().Set("X-Request-ID", reqID)
				ctx = xctx.WithRequestID(ctx, reqID)
			}

			rawToken := cfg.TokenSource(r)
			if rawToken == "" {
				if isPublic || cfg.Optional {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeJSONError(w, http.StatusUnauthorized, "missing token")
				return
			}

			claims, err := cfg.VerifyFn(ctx, rawToken)
			if err != nil {
				if isPublic || cfg.Optional {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			cfg.ClaimsMapper(scope, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// matchesPublicPath supports exact public endpoints by default. A configured
// trailing slash explicitly denotes a public route group.
func matchesPublicPath(cleanPath, configuredPath string) bool {
	if configuredPath == "" {
		return false
	}
	if strings.HasSuffix(configuredPath, "/") {
		return strings.HasPrefix(cleanPath+"/", configuredPath)
	}
	return cleanPath == path.Clean(configuredPath)
}

func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && v[:7] == "Bearer " {
		return v[7:]
	}
	return ""
}

func CookieToken(cookieName string) func(r *http.Request) string {
	return func(r *http.Request) string {
		c, err := r.Cookie(cookieName)
		if err != nil {
			return ""
		}
		return c.Value
	}
}

func QueryToken(param string) func(r *http.Request) string {
	return func(r *http.Request) string {
		return r.URL.Query().Get(param)
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":"Unauthorized","message":%q}`, msg)
}
