package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type rewriteTransport struct{ target *url.URL }

func (transport rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	parsed := *request.URL
	parsed.Scheme, parsed.Host = transport.target.Scheme, transport.target.Host
	cloned.URL, cloned.Host, cloned.RequestURI = &parsed, transport.target.Host, ""
	return http.DefaultTransport.RoundTrip(cloned)
}

type oidcFixture struct {
	t                   *testing.T
	server              *httptest.Server
	issuer              string
	clientID            string
	privateKey          *rsa.PrivateKey
	jwksKey             *rsa.PublicKey
	mu                  sync.Mutex
	claims              jwt.MapClaims
	wrongSigningKey     *rsa.PrivateKey
	wantVerifier        string
	appleClientKey      *ecdsa.PrivateKey
	appleTeam           string
	appleKeyID          string
	appleClientID       string
	appleSecretVerified bool
}

func newOIDCFixture(t *testing.T, issuer, clientID string) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &oidcFixture{t: t, issuer: issuer, clientID: clientID, privateKey: key, jwksKey: &key.PublicKey}
	fixture.claims = fixture.validClaims("nonce-123")
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *oidcFixture) validClaims(nonce string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": fixture.issuer, "sub": "provider-subject-123", "aud": fixture.clientID,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Add(-time.Second).Unix(),
		"email": "verified@example.test", "email_verified": true, "nonce": nonce,
	}
}

func (fixture *oidcFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	claims := cloneClaims(fixture.claims)
	signingKey := fixture.privateKey
	if fixture.wrongSigningKey != nil {
		signingKey = fixture.wrongSigningKey
	}
	wantVerifier, appleKey, appleTeam, appleKeyID, appleClientID := fixture.wantVerifier, fixture.appleClientKey, fixture.appleTeam, fixture.appleKeyID, fixture.appleClientID
	fixture.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeTestJSON(w, map[string]any{
			"issuer":                                fixture.issuer,
			"authorization_endpoint":                fixture.authorizationEndpoint(),
			"token_endpoint":                        fixture.tokenEndpoint(),
			"jwks_uri":                              fixture.jwksEndpoint(),
			"response_types_supported":              []string{"code", "id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks", "/oauth2/v3/certs", "/auth/keys", "/.well-known/oauth/openid/jwks/":
		writeTestJSON(w, map[string]any{"keys": []any{rsaJWK(fixture.jwksKey)}})
	case "/token", "/auth/token", "/v27.0/oauth/access_token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/v27.0/oauth/access_token" && (r.Method != http.MethodGet || r.Form.Get("client_secret") != "" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache") {
			http.Error(w, "Facebook exchange must use GET with PKCE, no app secret, and no caching", http.StatusBadRequest)
			return
		}
		if wantVerifier != "" && r.Form.Get("code_verifier") != wantVerifier {
			http.Error(w, "bad verifier", http.StatusBadRequest)
			return
		}
		if appleKey != nil {
			if err := verifyAppleClientSecret(r.Form.Get("client_secret"), appleKey, appleTeam, appleKeyID, appleClientID); err != nil {
				fixture.t.Errorf("Apple client secret validation: %v", err)
				http.Error(w, "bad client secret", http.StatusBadRequest)
				return
			}
			fixture.mu.Lock()
			fixture.appleSecretVerified = true
			fixture.mu.Unlock()
		}
		rawToken, err := signedIDToken(signingKey, claims)
		if err != nil {
			fixture.t.Errorf("sign test ID token: %v", err)
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		writeTestJSON(w, map[string]any{"access_token": "access-test", "token_type": "Bearer", "expires_in": 300, "id_token": rawToken})
	case "/user":
		writeTestJSON(w, map[string]any{"id": 123456})
	case "/user/emails":
		writeTestJSON(w, []map[string]any{{"email": "verified@example.test", "primary": true, "verified": true}})
	default:
		http.NotFound(w, r)
	}
}

func (fixture *oidcFixture) httpClient() *http.Client {
	target, err := url.Parse(fixture.server.URL)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return &http.Client{Transport: rewriteTransport{target: target}, Timeout: 5 * time.Second}
}

func (fixture *oidcFixture) authorizationEndpoint() string {
	if strings.Contains(fixture.issuer, "accounts.google.com") {
		return "https://accounts.google.com/o/oauth2/v2/auth"
	}
	return "https://appleid.apple.com/auth/authorize"
}

func (fixture *oidcFixture) tokenEndpoint() string {
	if strings.Contains(fixture.issuer, "accounts.google.com") {
		return "https://oauth2.googleapis.com/token"
	}
	return "https://appleid.apple.com/auth/token"
}

func (fixture *oidcFixture) jwksEndpoint() string {
	if strings.Contains(fixture.issuer, "accounts.google.com") {
		return "https://www.googleapis.com/oauth2/v3/certs"
	}
	return "https://appleid.apple.com/auth/keys"
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func cloneClaims(input jwt.MapClaims) jwt.MapClaims {
	cloned := jwt.MapClaims{}
	maps.Copy(cloned, input)
	return cloned
}

func signedIDToken(key *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	return token.SignedString(key)
}

func rsaJWK(key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "use": "sig", "kid": "test-key-1", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func verifyAppleClientSecret(encoded string, publicKey *ecdsa.PrivateKey, team, keyID, clientID string) error {
	token, err := jwt.Parse(encoded, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected algorithm %s", token.Method.Alg())
		}
		if token.Header["kid"] != keyID {
			return nil, errors.New("unexpected key ID")
		}
		return &publicKey.PublicKey, nil
	})
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["iss"] != team || claims["sub"] != clientID || claims["aud"] != "https://appleid.apple.com" {
		return errors.New("unexpected Apple client secret claims")
	}
	return nil
}

func TestGoogleCallbackVerifiesRealOIDCTokenSignatureClaimsNonceAndPKCE(t *testing.T) {
	const issuer, clientID, redirect = "https://accounts.google.com", "google-client", "https://nexss.example.test/auth/oauth/google/callback"
	fixture := newOIDCFixture(t, issuer, clientID)
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	fixture.wantVerifier = verifier
	provider, err := NewGoogleProvider(context.Background(), GoogleProviderConfig{ClientID: clientID, ClientSecret: "google-secret", RedirectURL: redirect, HTTPClient: fixture.httpClient()})
	if err != nil {
		t.Fatal(err)
	}
	state, nonce := "state-test", "nonce-123"
	authorizationURL, err := provider.AuthorizationURL(context.Background(), state, nonce, verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	challenge, _ := PKCEChallenge(verifier)
	if parsed.Query().Get("state") != state || parsed.Query().Get("nonce") != nonce || parsed.Query().Get("code_challenge") != challenge || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("incomplete OAuth request: %s", authorizationURL)
	}
	identity, err := provider.Complete(context.Background(), "test-code", nonce, verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != "google" || identity.Subject != "provider-subject-123" || identity.Email != "verified@example.test" || !identity.EmailVerified {
		t.Fatalf("identity=%+v", identity)
	}

	invalidCases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"wrong nonce", func(claims jwt.MapClaims) { claims["nonce"] = "attacker-nonce" }},
		{"wrong audience", func(claims jwt.MapClaims) { claims["aud"] = "other-client" }},
		{"expired token", func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"unverified email", func(claims jwt.MapClaims) { claims["email_verified"] = false }},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.validClaims(nonce)
			test.mutate(claims)
			fixture.mu.Lock()
			fixture.claims, fixture.wrongSigningKey = claims, nil
			fixture.mu.Unlock()
			if _, err := provider.Complete(context.Background(), "test-code", nonce, verifier, redirect); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
	t.Run("wrong signature", func(t *testing.T) {
		claims := fixture.validClaims(nonce)
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		fixture.mu.Lock()
		fixture.claims, fixture.wrongSigningKey = claims, wrong
		fixture.mu.Unlock()
		if _, err := provider.Complete(context.Background(), "test-code", nonce, verifier, redirect); err == nil {
			t.Fatal("ID token with wrong signing key accepted")
		}
	})
}

func TestFacebookCallbackVerifiesOIDCSignatureClaimsNonceAndPKCE(t *testing.T) {
	const clientID, redirect = "facebook-app-id", "https://nexss.example.test/auth/oauth/facebook/callback"
	fixture := newOIDCFixture(t, facebookOIDCIssuer, clientID)
	fixture.mu.Lock()
	fixture.claims = fixture.validClaims("facebook-nonce")
	delete(fixture.claims, "email_verified")
	fixture.mu.Unlock()
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	fixture.wantVerifier = verifier
	provider, err := NewFacebookProvider(FacebookProviderConfig{ClientID: clientID, RedirectURL: redirect, HTTPClient: fixture.httpClient()})
	if err != nil {
		t.Fatal(err)
	}
	if provider.CallbackMethod() != http.MethodGet {
		t.Fatalf("callback method=%s", provider.CallbackMethod())
	}
	authorizationURL, err := provider.AuthorizationURL(context.Background(), "facebook-state", "facebook-nonce", verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := PKCEChallenge(verifier)
	if parsed.Host != "www.facebook.com" || parsed.Path != "/v27.0/dialog/oauth" || parsed.Query().Get("state") != "facebook-state" || parsed.Query().Get("nonce") != "facebook-nonce" || parsed.Query().Get("code_challenge") != challenge || parsed.Query().Get("code_challenge_method") != "S256" || !strings.Contains(parsed.Query().Get("scope"), "openid") || !strings.Contains(parsed.Query().Get("scope"), "email") {
		t.Fatalf("incomplete Facebook OIDC/PKCE request: %s", authorizationURL)
	}
	identity, err := provider.Complete(context.Background(), "facebook-code", "facebook-nonce", verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != "facebook" || identity.Subject != "provider-subject-123" || identity.Email != "verified@example.test" || identity.EmailVerified {
		t.Fatalf("identity=%+v; Facebook email without an explicit email_verified claim must remain unverified", identity)
	}

	invalidCases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"wrong issuer", func(claims jwt.MapClaims) { claims["iss"] = "https://evil.example" }},
		{"wrong audience", func(claims jwt.MapClaims) { claims["aud"] = "another-app" }},
		{"wrong nonce", func(claims jwt.MapClaims) { claims["nonce"] = "attacker-nonce" }},
		{"expired token", func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"future issued-at", func(claims jwt.MapClaims) { claims["iat"] = time.Now().Add(10 * time.Minute).Unix() }},
		{"multiple audiences without authorized party", func(claims jwt.MapClaims) { claims["aud"] = []string{clientID, "another-app"} }},
		{"wrong authorized party", func(claims jwt.MapClaims) { claims["azp"] = "another-app" }},
		{"malformed email", func(claims jwt.MapClaims) { claims["email"] = "not-an-email" }},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.validClaims("facebook-nonce")
			test.mutate(claims)
			fixture.mu.Lock()
			fixture.claims, fixture.wrongSigningKey = claims, nil
			fixture.mu.Unlock()
			if _, err := provider.Complete(context.Background(), "facebook-code", "facebook-nonce", verifier, redirect); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
	t.Run("wrong signature", func(t *testing.T) {
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		fixture.mu.Lock()
		fixture.claims, fixture.wrongSigningKey = fixture.validClaims("facebook-nonce"), wrong
		fixture.mu.Unlock()
		if _, err := provider.Complete(context.Background(), "facebook-code", "facebook-nonce", verifier, redirect); err == nil {
			t.Fatal("ID token with wrong signing key accepted")
		}
	})
	t.Run("missing email remains usable only as a linked identity", func(t *testing.T) {
		claims := fixture.validClaims("facebook-nonce")
		delete(claims, "email")
		delete(claims, "email_verified")
		fixture.mu.Lock()
		fixture.claims, fixture.wrongSigningKey = claims, nil
		fixture.mu.Unlock()
		identity, err := provider.Complete(context.Background(), "facebook-code", "facebook-nonce", verifier, redirect)
		if err != nil || identity.Email != "" || identity.EmailVerified {
			t.Fatalf("identity=%+v err=%v", identity, err)
		}
	})
}

func TestGitHubCallbackRequiresPKCEAndVerifiedPrimaryEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("code_verifier") != "github-code-verifier-01234567890123456789012345678901234567890" {
				http.Error(w, "bad verifier", http.StatusBadRequest)
				return
			}
			writeTestJSON(w, map[string]any{"access_token": "github-access", "token_type": "bearer", "expires_in": 3600})
		case "/user":
			writeTestJSON(w, map[string]any{"id": 987654})
		case "/user/emails":
			writeTestJSON(w, []map[string]any{{"email": "verified@example.test", "primary": true, "verified": true}, {"email": "old@example.test", "primary": false, "verified": true}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	provider, err := NewGitHubProvider(GitHubProviderConfig{ClientID: "github-client", ClientSecret: "github-secret", RedirectURL: "https://nexss.example.test/auth/oauth/github/callback", HTTPClient: &http.Client{Transport: rewriteTransport{target: parsed}, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "github-code-verifier-01234567890123456789012345678901234567890"
	authorizationURL, err := provider.AuthorizationURL(context.Background(), "state-github", "nonce-unused", verifier, "https://nexss.example.test/auth/oauth/github/callback")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := url.Parse(authorizationURL)
	challenge, _ := PKCEChallenge(verifier)
	if auth.Query().Get("code_challenge") != challenge || auth.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE absent: %s", authorizationURL)
	}
	identity, err := provider.Complete(context.Background(), "github-code", "", verifier, "https://nexss.example.test/auth/oauth/github/callback")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "987654" || identity.Email != "verified@example.test" || !identity.EmailVerified {
		t.Fatalf("identity=%+v", identity)
	}
	if _, err := verifiedGitHubIdentity(githubUser{ID: "123"}, []githubEmail{{Email: "x@example.test", Primary: true, Verified: false}}); err == nil {
		t.Fatal("unverified primary email accepted")
	}
	if _, err := verifiedGitHubIdentity(githubUser{ID: "123"}, []githubEmail{{Email: "one@example.test", Primary: true, Verified: true}, {Email: "two@example.test", Primary: true, Verified: true}}); err == nil {
		t.Fatal("ambiguous primary emails accepted")
	}
	for _, test := range []struct {
		name   string
		user   githubUser
		emails []githubEmail
	}{
		{name: "missing subject", user: githubUser{}, emails: []githubEmail{{Email: "x@example.test", Primary: true, Verified: true}}},
		{name: "non-numeric subject", user: githubUser{ID: "not-numeric"}, emails: []githubEmail{{Email: "x@example.test", Primary: true, Verified: true}}},
		{name: "missing primary", user: githubUser{ID: "123"}, emails: []githubEmail{{Email: "x@example.test", Primary: false, Verified: true}}},
		{name: "malformed email", user: githubUser{ID: "123"}, emails: []githubEmail{{Email: "bad-address", Primary: true, Verified: true}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifiedGitHubIdentity(test.user, test.emails); err == nil {
				t.Fatal("invalid GitHub identity accepted")
			}
		})
	}
}

func TestAppleCallbackVerifiesClientSecretAndOIDCToken(t *testing.T) {
	const issuer, clientID, redirect = "https://appleid.apple.com", "com.nexss.web", "https://nexss.example.test/auth/oauth/apple/callback"
	fixture := newOIDCFixture(t, issuer, clientID)
	fixture.mu.Lock()
	fixture.claims = fixture.validClaims("apple-nonce")
	fixture.mu.Unlock()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.appleClientKey, fixture.appleTeam, fixture.appleKeyID, fixture.appleClientID = clientKey, "TEAM123ABC", "KEYID12345", clientID
	provider, err := NewAppleProvider(context.Background(), AppleProviderConfig{
		ClientID: clientID, TeamID: fixture.appleTeam, KeyID: fixture.appleKeyID,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), RedirectURL: redirect, HTTPClient: fixture.httpClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.CallbackMethod() != http.MethodPost {
		t.Fatalf("callback method=%s", provider.CallbackMethod())
	}
	verifier, _ := NewPKCEVerifier()
	authorizationURL, err := provider.AuthorizationURL(context.Background(), "apple-state", "apple-nonce", verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	if parsed.Query().Get("response_mode") != "form_post" {
		t.Fatalf("Apple form_post missing: %s", authorizationURL)
	}
	identity, err := provider.Complete(context.Background(), "apple-code", "apple-nonce", verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != "apple" || identity.Email != "verified@example.test" || !identity.EmailVerified {
		t.Fatalf("identity=%+v", identity)
	}
	fixture.mu.Lock()
	verified := fixture.appleSecretVerified
	fixture.mu.Unlock()
	if !verified {
		t.Fatal("Apple token request did not carry a verifiable ES256 client secret")
	}
}

func TestProviderRedirectAndAppleKeyConfigurationValidation(t *testing.T) {
	if _, err := NewGoogleProvider(context.Background(), GoogleProviderConfig{ClientID: "x", ClientSecret: "secret", RedirectURL: "https://nexss.test/callback?next=evil"}); err == nil {
		t.Fatal("callback URL with query accepted")
	}
	if _, err := NewAppleProvider(context.Background(), AppleProviderConfig{ClientID: "x", TeamID: "TEAM123ABC", KeyID: "KEYID12345", PrivateKeyPEM: []byte("not a key"), RedirectURL: "https://nexss.test/callback"}); err == nil {
		t.Fatal("invalid Apple key accepted")
	}
	appleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	applePEM, err := x509.MarshalECPrivateKey(appleKey)
	if err != nil {
		t.Fatal(err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: applePEM})
	if _, err := parseApplePrivateKey(append(append([]byte(nil), validPEM...), validPEM...)); err == nil {
		t.Fatal("Apple key parser accepted trailing PEM data")
	}
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurveDER, err := x509.MarshalECPrivateKey(wrongCurve)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseApplePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: wrongCurveDER})); err == nil {
		t.Fatal("Apple key parser accepted a non-P-256 curve")
	}
	if _, err := NewFacebookProvider(FacebookProviderConfig{ClientID: "facebook-app", RedirectURL: "https://nexss.test/callback?next=evil"}); err == nil {
		t.Fatal("Facebook callback URL with query accepted")
	}
	if err := ValidateProviderRedirectURL("http://evil.example.test/callback"); err == nil {
		t.Fatal("non-loopback HTTP callback accepted")
	}
}

func TestVerifiedEmailClaimRequiresJSONBoolean(t *testing.T) {
	for _, test := range []struct {
		claim string
		want  bool
	}{
		{claim: `true`, want: true},
		{claim: `false`, want: false},
		{claim: `"true"`, want: false},
		{claim: `"false"`, want: false},
		{claim: `null`, want: false},
		{claim: `not-json`, want: false},
	} {
		if got := verifiedClaim(json.RawMessage(test.claim)); got != test.want {
			t.Errorf("verifiedClaim(%s)=%v, want %v", test.claim, got, test.want)
		}
	}
}

func TestOIDCFixtureHasValidJWTHeaders(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "issuer", "aud": "client", "sub": "subject", "exp": time.Now().Add(time.Minute).Unix()}
	raw, err := signedIDToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("JWT is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded["sub"] != "subject" {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
}
