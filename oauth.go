// Path: nexss/plugins/auth/oauth.go
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/transport/thttp"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type oauthProviderState struct {
	oauth2Cfg *oauth2.Config
	verifier  *oidc.IDTokenVerifier
}

// initOAuthProviders sets up the discovery documents for OIDC providers at boot.
func (p *Plugin) initOAuthProviders(ctx context.Context) error {
	p.oauthStates = make(map[string]*oauthProviderState)

	for _, cfg := range p.cfg.OAuthProviders {
		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return fmt.Errorf("auth: failed to init OIDC provider %q: %w", cfg.Provider, err)
		}

		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{oidc.ScopeOpenID, "profile", "email"}
		}

		p.oauthStates[cfg.Provider] = &oauthProviderState{
			oauth2Cfg: &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Endpoint:     provider.Endpoint(),
				Scopes:       scopes,
			},
			verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		}
	}
	return nil
}

// buildOAuthLogin redirects the user to the consent screen.
func (p *Plugin) buildOAuthLogin() action.AnyAction {
	return action.New[any, any]("auth.oauth.login", nil).
		Route(thttp.RawHandler("GET", "/auth/oauth/{provider}/login", func(w http.ResponseWriter, r *http.Request) {
			providerName := r.PathValue("provider")
			state, ok := p.oauthStates[providerName]
			if !ok {
				http.Error(w, "Unknown OAuth provider", http.StatusBadRequest)
				return
			}

			// Generate CSRF state
			b := make([]byte, 32)
			rand.Read(b)
			stateStr := base64.RawURLEncoding.EncodeToString(b)

			// Store state in a secure HttpOnly cookie (valid for 10 mins)
			http.SetCookie(w, &http.Cookie{
				Name:     "oauth_state",
				Value:    stateStr,
				Path:     "/auth/oauth/",
				MaxAge:   600,
				HttpOnly: true,
				Secure:   !p.cfg.DesktopMode,
				SameSite: http.SameSiteLaxMode,
			})

			url := state.oauth2Cfg.AuthCodeURL(stateStr, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		})).Build()
}

// buildOAuthCallback handles the return from Google/Apple, validates, and logs the user in.
func (p *Plugin) buildOAuthCallback() action.AnyAction {
	return action.New[any, any]("auth.oauth.callback", nil).
		Route(thttp.RawHandler("GET", "/auth/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			providerName := r.PathValue("provider")
			pState, ok := p.oauthStates[providerName]
			if !ok {
				http.Error(w, "Unknown OAuth provider", http.StatusBadRequest)
				return
			}

			// 1. Verify CSRF State
			stateCookie, err := r.Cookie("oauth_state")
			if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
				http.Error(w, "Invalid OAuth state (CSRF)", http.StatusBadRequest)
				return
			}

			// 2. Exchange Code for Token
			oauth2Token, err := pState.oauth2Cfg.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// 3. Extract and Verify OIDC ID Token
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
				return
			}

			idToken, err := pState.verifier.Verify(ctx, rawIDToken)
			if err != nil {
				http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// 4. Extract Profile Data
			var claims struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			}
			if err := idToken.Claims(&claims); err != nil {
				http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
				return
			}

			providerUserID := idToken.Subject // Unique ID from Google/Microsoft

			// 5. User Match & Link Logic
			var finalUser *User

			// Check if OAuth account already exists
			userID, err := p.cfg.Store.GetOAuthAccount(ctx, providerName, providerUserID)
			if err == nil && userID != "" {
				// Existing linked user
				finalUser, _ = p.cfg.Store.GetUserByID(ctx, userID)
			}

			if finalUser == nil {
				// Check if email already exists in DB
				existingUser, _ := p.cfg.Store.GetUserByEmail(ctx, claims.Email)
				if existingUser != nil {
					if !claims.EmailVerified {
						http.Error(w, "Unverified OAuth email cannot be linked", http.StatusForbidden)
						return
					}
					// Link new OAuth account to existing email account
					finalUser = existingUser
					_ = p.cfg.Store.LinkOAuthAccount(ctx, finalUser.ID, providerName, providerUserID)
				} else {
					// Create brand new user
					finalUser = &User{
						ID:        generateID(),
						Email:     claims.Email,
						Password:  []byte(generateID()), // Random impossible password
						Verified:  claims.EmailVerified,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					}
					if err := p.cfg.Store.CreateUser(ctx, finalUser); err != nil {
						http.Error(w, "Failed to create user", http.StatusInternalServerError)
						return
					}
					_ = p.cfg.Store.LinkOAuthAccount(ctx, finalUser.ID, providerName, providerUserID)
				}
			}

			// 6. Issue Nexss JWT Tokens
			// Note: We use empty tenant for global logins; tenant context is established post-login usually.
			res, err := p.issueTokens(ctx, finalUser, "")
			if err != nil {
				http.Error(w, "Failed to issue tokens", http.StatusInternalServerError)
				return
			}

			// 7. Redirect to Frontend with Tokens (SPA Pattern)
			// Pass tokens securely via hash fragment so they don't hit server access logs
			targetURL := fmt.Sprintf("%s/oauth-success#access_token=%s&refresh_token=%s",
				p.cfg.BaseURL, res.Token.Access, res.Token.Refresh)

			http.Redirect(w, r, targetURL, http.StatusFound)
		})).Build()
}

// DTO dla frontendu
type OAuthProviderDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Wystawia listę skonfigurowanych dostawców OAuth, by UI mogło wyrenderować przyciski dynamicznie.
func (p *Plugin) buildOAuthProviders() action.AnyAction {
	return action.New("auth.oauth.providers", func(ctx context.Context, _ struct{}) ([]OAuthProviderDTO, error) {
		var res []OAuthProviderDTO
		for _, cfg := range p.cfg.OAuthProviders {
			// Prosta kapitalizacja, np. "google" -> "Google", "microsoft" -> "Microsoft"
			name := cfg.Provider
			if len(name) > 0 {
				name = strings.ToUpper(name[:1]) + name[1:]
			}

			res = append(res, OAuthProviderDTO{
				ID:   cfg.Provider,
				Name: name,
				URL:  fmt.Sprintf("/auth/oauth/%s/login", cfg.Provider),
			})
		}
		return res, nil
	}).
		Description("Zwraca listę dostępnych dostawców logowania SSO").
		Tag("auth", "public").
		Route(thttp.GET("/auth/oauth-providers")). // <-- Path updated here
		Build()
}
