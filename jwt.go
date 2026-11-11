package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	keyOnce   sync.Once
)

func InitKeys(privPEM, pubPEM []byte) error {
	var err error
	if signKey, err = jwt.ParseRSAPrivateKeyFromPEM(privPEM); err != nil {
		return fmt.Errorf("auth: invalid private key: %w", err)
	}
	if verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(pubPEM); err != nil {
		return fmt.Errorf("auth: invalid public key: %w", err)
	}
	return nil
}

func InitTempKeys() error {
	var initErr error
	keyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			initErr = err
			return
		}
		signKey = key
		verifyKey = &key.PublicKey
	})
	return initErr
}

func InitOrLoadPersistentKeys(privPath, pubPath string) error {
	priv, err1 := os.ReadFile(privPath)
	pub, err2 := os.ReadFile(pubPath)
	if err1 == nil && err2 == nil {
		return InitKeys(priv, pub)
	}
	if err := InitTempKeys(); err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signKey)})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(verifyKey)})
	_ = os.WriteFile(privPath, privPEM, 0o600)
	_ = os.WriteFile(pubPath, pubPEM, 0o644)
	return nil
}

type Tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func GenerateTokens(tenantID, userID, role string) (*Tokens, error) {
	if signKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	now := time.Now()
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  userID,
		"ten":  tenantID,
		"role": role,
		"exp":  now.Add(15 * time.Minute).Unix(),
		"iat":  now.Unix(),
		"jti":  fmt.Sprintf("a-%s-%d", userID, now.UnixNano()),
	}).SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}
	refresh, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": userID,
		"ten": tenantID,
		"exp": now.Add(30 * 24 * time.Hour).Unix(),
		"jti": fmt.Sprintf("r-%s-%d", userID, now.UnixNano()),
	}).SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign refresh token: %w", err)
	}
	return &Tokens{Access: access, Refresh: refresh}, nil
}

// GenerateTokensWithClaims preserves the historical 30-day refresh-token
// lifetime for callers that do not use the authentication plugin.
func GenerateTokensWithClaims(claims jwt.MapClaims) (*Tokens, error) {
	return generateTokensWithClaims(claims, 30*24*time.Hour)
}

func generateTokensWithClaims(claims jwt.MapClaims, refreshTTL time.Duration) (*Tokens, error) {
	if signKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	if refreshTTL <= 0 {
		return nil, errors.New("auth: refresh token TTL must be positive")
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access: %w", err)
	}

	refreshClaims := jwt.MapClaims{
		"sub": claims["sub"],
		"exp": time.Now().Add(refreshTTL).Unix(),
	}
	if jti, ok := claims["jti"]; ok {
		refreshClaims["jti"] = jti
	}
	if ten, ok := claims["ten"]; ok {
		refreshClaims["ten"] = ten
	}

	refresh, err := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims).SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign refresh: %w", err)
	}
	return &Tokens{Access: access, Refresh: refresh}, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	if verifyKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return verifyKey, nil
	}, jwt.WithLeeway(5*time.Second))
}
