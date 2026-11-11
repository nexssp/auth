package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const providerHTTPBodyLimit = 256 << 10

const (
	facebookOIDCIssuer = "https://www.facebook.com"
	facebookOIDCJWKS   = "https://www.facebook.com/.well-known/oauth/openid/jwks/"
	facebookAuthURL    = "https://www.facebook.com/v27.0/dialog/oauth"
	facebookTokenURL   = "https://graph.facebook.com/v27.0/oauth/access_token"
)

// GoogleProviderConfig contains only host-supplied Google OAuth settings. The
// redirect URI must be the exact canonical callback registered with Google.
type GoogleProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
}

// GitHubProviderConfig contains only host-supplied GitHub OAuth settings.
type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
}

// AppleProviderConfig contains host-owned Apple Sign in with Apple credentials.
type AppleProviderConfig struct {
	ClientID      string
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte
	RedirectURL   string
	HTTPClient    *http.Client
}

// FacebookProviderConfig contains host-supplied Facebook Login settings. The
// adapter uses PKCE and deliberately does not send an app secret in the
// token-exchange URL.
type FacebookProviderConfig struct {
	ClientID    string
	RedirectURL string
	HTTPClient  *http.Client
}

type oidcProvider struct {
	name                 string
	redirect             string
	config               oauth2.Config
	verifier             *oidc.IDTokenVerifier
	httpClient           *http.Client
	apple                *appleClientSecretConfig
	requireVerifiedEmail bool
}

// NewGoogleProvider creates an OIDC adapter pinned to Google's issuer and
// validates issuer, audience, signature, time claims, nonce, and verified email.
func NewGoogleProvider(ctx context.Context, config GoogleProviderConfig) (OAuthProvider, error) {
	if err := validateOAuthClient(config.ClientID, config.ClientSecret, config.RedirectURL); err != nil {
		return nil, fmt.Errorf("auth: configure Google OAuth: %w", err)
	}
	return newOIDCProvider(ctx, "google", "https://accounts.google.com", config.ClientID, config.ClientSecret, config.RedirectURL, []string{oidc.ScopeOpenID, "email", "profile"}, config.HTTPClient, nil)
}

// NewFacebookProvider creates a Facebook Login OIDC adapter. Meta currently
// documents this manually built OIDC/PKCE flow as testing; its signed email
// claim is not treated as verified unless the token explicitly says so.
func NewFacebookProvider(config FacebookProviderConfig) (OAuthProvider, error) {
	if config.ClientID == "" || len(config.ClientID) > 255 || hasControl(config.ClientID) || !validCallbackURL(config.RedirectURL) {
		return nil, errors.New("auth: invalid Facebook client ID or callback URL")
	}
	client := safeProviderHTTPClient(config.HTTPClient)
	providerCtx := withProviderHTTPClient(context.Background(), client)
	verifier := oidc.NewVerifier(facebookOIDCIssuer, oidc.NewRemoteKeySet(providerCtx, facebookOIDCJWKS), &oidc.Config{
		ClientID: config.ClientID, SupportedSigningAlgs: []string{"RS256"},
	})
	return &oidcProvider{
		name: "facebook", redirect: config.RedirectURL,
		config: oauth2.Config{
			ClientID:    config.ClientID,
			Endpoint:    oauth2.Endpoint{AuthURL: facebookAuthURL, TokenURL: facebookTokenURL},
			RedirectURL: config.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "email"},
		},
		verifier: verifier, httpClient: client,
	}, nil
}

// NewAppleProvider creates Apple's OIDC adapter. The callback uses form_post;
// its browser-session cookie must therefore be configured by the host for that
// cross-site POST (PHP uses Secure, HttpOnly, SameSite=None).
func NewAppleProvider(ctx context.Context, config AppleProviderConfig) (OAuthProvider, error) {
	if config.ClientID == "" || len(config.ClientID) > 255 || hasControl(config.ClientID) || !validCallbackURL(config.RedirectURL) {
		return nil, errors.New("auth: invalid Apple client ID or callback URL")
	}
	if !providerIDPattern.MatchString(config.TeamID) || !providerIDPattern.MatchString(config.KeyID) {
		return nil, errors.New("auth: Apple team ID and key ID must be 10 uppercase letters or digits")
	}
	key, err := parseApplePrivateKey(config.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("auth: parse Apple private key: %w", err)
	}
	secret := &appleClientSecretConfig{clientID: config.ClientID, teamID: config.TeamID, keyID: config.KeyID, privateKey: key}
	client := safeProviderHTTPClient(config.HTTPClient)
	providerCtx := withProviderHTTPClient(ctx, client)
	provider, err := oidc.NewProvider(providerCtx, "https://appleid.apple.com")
	if err != nil {
		return nil, fmt.Errorf("auth: discover Apple OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &oidcProvider{
		name: "apple", redirect: config.RedirectURL,
		config: oauth2.Config{
			ClientID: config.ClientID, Endpoint: endpoint, RedirectURL: config.RedirectURL,
			Scopes: []string{oidc.ScopeOpenID, "email"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		httpClient: client, apple: secret, requireVerifiedEmail: true,
	}, nil
}

func newOIDCProvider(ctx context.Context, name, issuer, clientID, clientSecret, redirectURL string, scopes []string, httpClient *http.Client, apple *appleClientSecretConfig) (OAuthProvider, error) {
	client := safeProviderHTTPClient(httpClient)
	providerCtx := withProviderHTTPClient(ctx, client)
	provider, err := oidc.NewProvider(providerCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: discover %s OIDC provider: %w", name, err)
	}
	return &oidcProvider{
		name: name, redirect: redirectURL,
		config:   oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: provider.Endpoint(), RedirectURL: redirectURL, Scopes: scopes},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}), httpClient: client, apple: apple, requireVerifiedEmail: true,
	}, nil
}

func (provider *oidcProvider) Name() string { return provider.name }

func (provider *oidcProvider) CallbackMethod() string {
	if provider.name == "apple" {
		return http.MethodPost
	}
	return http.MethodGet
}

func (provider *oidcProvider) AuthorizationURL(ctx context.Context, state, nonce, verifier, redirectURL string) (string, error) {
	if !constantTimeEqual(provider.redirect, redirectURL) || state == "" || nonce == "" {
		return "", ErrInvalidInput
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return "", err
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if provider.name == "google" {
		options = append(options, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	if provider.name == "apple" {
		options = append(options, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	return provider.config.AuthCodeURL(state, options...), nil
}

func (provider *oidcProvider) Complete(ctx context.Context, code, nonce, verifier, redirectURL string) (ProviderIdentity, error) {
	if code == "" || len(code) > 4096 || hasControl(code) || nonce == "" || !constantTimeEqual(provider.redirect, redirectURL) {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	config := provider.config
	if provider.apple != nil {
		secret, err := provider.apple.sign(provider.timeNow())
		if err != nil {
			return ProviderIdentity{}, err
		}
		config.ClientSecret = secret
	}
	providerCtx := withProviderHTTPClient(ctx, provider.httpClient)
	var rawIDToken string
	var err error
	if provider.name == "facebook" {
		rawIDToken, err = provider.exchangeFacebookCode(providerCtx, code, verifier, redirectURL)
	} else {
		var token *oauth2.Token
		token, err = config.Exchange(providerCtx, code, oauth2.VerifierOption(verifier))
		if err == nil {
			rawIDToken, _ = token.Extra("id_token").(string)
		}
	}
	if err != nil {
		return ProviderIdentity{}, fmt.Errorf("exchange %s authorization code: %w", provider.name, err)
	}
	if rawIDToken == "" || len(rawIDToken) > 16384 {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	idToken, err := provider.verifier.Verify(providerCtx, rawIDToken)
	if err != nil {
		return ProviderIdentity{}, fmt.Errorf("verify %s ID token: %w", provider.name, err)
	}
	var claims struct {
		Subject       string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
		Nonce         string          `json:"nonce"`
		Authorized    string          `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return ProviderIdentity{}, fmt.Errorf("decode %s ID token claims: %w", provider.name, err)
	}
	verified := verifiedClaim(claims.EmailVerified)
	email := normalizeEmail(claims.Email)
	now := provider.timeNow()
	wrongAuthorizedParty := claims.Authorized != "" && claims.Authorized != provider.config.ClientID
	missingAuthorizedParty := len(idToken.Audience) > 1 && claims.Authorized != provider.config.ClientID
	if claims.Subject == "" || len(claims.Subject) > 255 || hasControl(claims.Subject) || (claims.Email != "" && email == "") || (provider.requireVerifiedEmail && (email == "" || !verified)) || !constantTimeEqual(claims.Nonce, nonce) || wrongAuthorizedParty || missingAuthorizedParty || idToken.IssuedAt.IsZero() || idToken.IssuedAt.After(now.Add(5*time.Minute)) || !idToken.Expiry.After(now) {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	return ProviderIdentity{Provider: provider.name, Subject: claims.Subject, Email: email, EmailVerified: email != "" && verified}, nil
}

func (provider *oidcProvider) exchangeFacebookCode(ctx context.Context, code, verifier, redirectURL string) (string, error) {
	endpoint, err := url.Parse(provider.config.Endpoint.TokenURL)
	if err != nil {
		return "", ErrInvalidOAuthResponse
	}
	query := endpoint.Query()
	query.Set("client_id", provider.config.ClientID)
	query.Set("redirect_uri", redirectURL)
	query.Set("code", code)
	query.Set("code_verifier", verifier)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", ErrInvalidOAuthResponse
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Pragma", "no-cache")
	response, err := provider.httpClient.Do(request)
	if err != nil {
		// Do not return url.Error: Facebook's required GET URL contains the
		// one-use code and verifier, which must not be copied into logs.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("auth: Facebook token exchange request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrInvalidOAuthResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, providerHTTPBodyLimit+1))
	if err != nil || len(body) > providerHTTPBodyLimit {
		return "", ErrInvalidOAuthResponse
	}
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" || token.IDToken == "" || len(token.IDToken) > 16384 {
		return "", ErrInvalidOAuthResponse
	}
	return token.IDToken, nil
}

func (provider *oidcProvider) timeNow() time.Time { return time.Now() }

// githubProvider uses GitHub's stable numeric user ID and requires one verified
// primary email. It never treats the profile's unverified email as an identity.
type githubProvider struct {
	config     oauth2.Config
	httpClient *http.Client
}

// NewGitHubProvider creates the GitHub OAuth adapter with read:user and
// user:email scopes, state and PKCE validation handled by Service.
func NewGitHubProvider(config GitHubProviderConfig) (OAuthProvider, error) {
	if err := validateOAuthClient(config.ClientID, config.ClientSecret, config.RedirectURL); err != nil {
		return nil, fmt.Errorf("auth: configure GitHub OAuth: %w", err)
	}
	return &githubProvider{
		config: oauth2.Config{
			ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURL,
			Endpoint: oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token"},
			Scopes:   []string{"read:user", "user:email"},
		},
		httpClient: safeProviderHTTPClient(config.HTTPClient),
	}, nil
}

func (provider *githubProvider) Name() string           { return "github" }
func (provider *githubProvider) CallbackMethod() string { return http.MethodGet }

func (provider *githubProvider) AuthorizationURL(_ context.Context, state, nonce, verifier, redirectURL string) (string, error) {
	if !constantTimeEqual(provider.config.RedirectURL, redirectURL) || state == "" || nonce == "" {
		return "", ErrInvalidInput
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return "", err
	}
	return provider.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

func (provider *githubProvider) Complete(ctx context.Context, code, _, verifier, redirectURL string) (ProviderIdentity, error) {
	if code == "" || len(code) > 4096 || !constantTimeEqual(provider.config.RedirectURL, redirectURL) {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	providerCtx := withProviderHTTPClient(ctx, provider.httpClient)
	token, err := provider.config.Exchange(providerCtx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return ProviderIdentity{}, fmt.Errorf("exchange GitHub authorization code: %w", err)
	}
	client := oauth2.NewClient(providerCtx, oauth2.StaticTokenSource(token))
	client.Timeout = 12 * time.Second
	user, err := getGitHubJSON[githubUser](providerCtx, client, "https://api.github.com/user")
	if err != nil {
		return ProviderIdentity{}, fmt.Errorf("read GitHub user: %w", err)
	}
	var emails []githubEmail
	for page := 1; page <= 5; page++ {
		endpoint := "https://api.github.com/user/emails?per_page=100&page=" + strconv.Itoa(page)
		entries, err := getGitHubJSON[[]githubEmail](providerCtx, client, endpoint)
		if err != nil {
			return ProviderIdentity{}, fmt.Errorf("read GitHub verified emails: %w", err)
		}
		emails = append(emails, entries...)
		if len(entries) < 100 {
			break
		}
	}
	identity, err := verifiedGitHubIdentity(user, emails)
	if err != nil {
		return ProviderIdentity{}, err
	}
	return identity, nil
}

type githubUser struct {
	ID json.Number `json:"id"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func verifiedGitHubIdentity(user githubUser, emails []githubEmail) (ProviderIdentity, error) {
	subject := user.ID.String()
	if _, err := strconv.ParseUint(subject, 10, 64); err != nil || subject == "0" || len(subject) > 19 {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	primary := make(map[string]struct{})
	for _, entry := range emails {
		if !entry.Primary || !entry.Verified {
			continue
		}
		email := normalizeEmail(entry.Email)
		if email != "" {
			primary[email] = struct{}{}
		}
	}
	if len(primary) != 1 {
		return ProviderIdentity{}, ErrInvalidOAuthResponse
	}
	for email := range primary {
		return ProviderIdentity{Provider: "github", Subject: subject, Email: email, EmailVerified: true}, nil
	}
	return ProviderIdentity{}, ErrInvalidOAuthResponse
}

func getGitHubJSON[T any](ctx context.Context, client *http.Client, endpoint string) (T, error) {
	var zero T
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "nexssp-auth")
	response, err := client.Do(request)
	if err != nil {
		return zero, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, providerHTTPBodyLimit+1))
	if err != nil {
		return zero, err
	}
	if len(body) > providerHTTPBodyLimit {
		return zero, errors.New("GitHub API response is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var result T
	if err := decoder.Decode(&result); err != nil {
		return zero, err
	}
	return result, nil
}

type appleClientSecretConfig struct {
	clientID   string
	teamID     string
	keyID      string
	privateKey *ecdsa.PrivateKey
}

func (config *appleClientSecretConfig) sign(now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": config.teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": config.clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = config.keyID
	signed, err := token.SignedString(config.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign Apple client secret: %w", err)
	}
	return signed, nil
}

func parseApplePrivateKey(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key must contain exactly one PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not ECDSA")
		}
		if validAppleSigningKey(key) {
			return key, nil
		}
		return nil, errors.New("private key is not P-256")
	}
	key, ecErr := x509.ParseECPrivateKey(block.Bytes)
	if ecErr != nil {
		return nil, err
	}
	if !validAppleSigningKey(key) {
		return nil, errors.New("private key is not P-256")
	}
	return key, nil
}

func validAppleSigningKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve != nil && key.Curve.Params().Name == "P-256" && key.D != nil
}

func validateOAuthClient(clientID, clientSecret, redirectURL string) error {
	if clientID == "" || len(clientID) > 255 || hasControl(clientID) || clientSecret == "" || len(clientSecret) > 512 || hasControl(clientSecret) || !validCallbackURL(redirectURL) {
		return ErrInvalidInput
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func safeProviderHTTPClient(client *http.Client) *http.Client {
	copy := &http.Client{Timeout: 12 * time.Second}
	if client != nil {
		*copy = *client
		if copy.Timeout == 0 {
			copy.Timeout = 12 * time.Second
		}
	}
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return copy
}

func withProviderHTTPClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

var providerIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

func verifiedClaim(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var value bool
	return json.Unmarshal(raw, &value) == nil && value
}

// ValidateProviderRedirectURL is exposed for host config checks. OAuth redirect
// URLs must be canonical HTTPS URLs; HTTP is permitted only for localhost or
// loopback development endpoints.
func ValidateProviderRedirectURL(value string) error {
	if !validCallbackURL(value) {
		return errors.New("callback URL must be canonical HTTPS or local loopback HTTP without query or fragment")
	}
	return nil
}
