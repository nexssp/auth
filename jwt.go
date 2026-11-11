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
	keyMu      sync.RWMutex
	signKey    *rsa.PrivateKey
	verifyKey  *rsa.PublicKey
	keyOnce    sync.Once
	errTempKey error
)

// InitKeys validates and installs a matching RSA key pair with at least 2048
// bits. Parsed keys are swapped together so signing and verification cannot see
// a partially initialized or mismatched pair.
func InitKeys(privPEM, pubPEM []byte) error {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		return fmt.Errorf("auth: invalid private key: %w", err)
	}
	if validateErr := privateKey.Validate(); validateErr != nil {
		return fmt.Errorf("auth: invalid private key: %w", validateErr)
	}
	if privateKey.N.BitLen() < 2048 {
		return errors.New("auth: RSA key must be at least 2048 bits")
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		return fmt.Errorf("auth: invalid public key: %w", err)
	}
	if publicKey.N.BitLen() < 2048 || publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		return errors.New("auth: RSA public and private keys must match and be at least 2048 bits")
	}

	keyMu.Lock()
	signKey, verifyKey = privateKey, publicKey
	keyMu.Unlock()
	return nil
}

// InitTempKeys generates one process-local 2048-bit RSA key pair if keys have
// not already been installed. The generated key is unsuitable for persistent
// production sessions because it changes when the process restarts.
func InitTempKeys() error {
	keyMu.RLock()
	initialized := signKey != nil && verifyKey != nil
	keyMu.RUnlock()
	if initialized {
		return nil
	}
	keyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			errTempKey = err
			return
		}
		keyMu.Lock()
		if signKey == nil && verifyKey == nil {
			signKey, verifyKey = key, &key.PublicKey
		}
		keyMu.Unlock()
	})
	return errTempKey
}

// InitOrLoadPersistentKeys loads a complete key pair, or creates one only when
// both files are absent. A partial or unreadable pair is an error, not a reason
// to silently replace credentials.
func InitOrLoadPersistentKeys(privPath, pubPath string) error {
	privatePEM, privateErr := os.ReadFile(privPath)
	publicPEM, publicErr := os.ReadFile(pubPath)
	if privateErr == nil && publicErr == nil {
		return InitKeys(privatePEM, publicPEM)
	}
	privateMissing := errors.Is(privateErr, os.ErrNotExist)
	publicMissing := errors.Is(publicErr, os.ErrNotExist)
	if privateErr != nil && !privateMissing {
		return fmt.Errorf("auth: read private key: %w", privateErr)
	}
	if publicErr != nil && !publicMissing {
		return fmt.Errorf("auth: read public key: %w", publicErr)
	}
	if !privateMissing || !publicMissing {
		return errors.New("auth: both persistent RSA key files must exist or neither")
	}
	if err := InitTempKeys(); err != nil {
		return fmt.Errorf("auth: generate persistent keys: %w", err)
	}
	privateKey, publicKey := currentKeys()
	if privateKey == nil || publicKey == nil {
		return errors.New("auth: keys not initialized")
	}
	privateBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	publicBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)})
	if err := os.WriteFile(privPath, privateBytes, 0o600); err != nil {
		return fmt.Errorf("auth: write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, publicBytes, 0o600); err != nil {
		return fmt.Errorf("auth: write public key: %w", err)
	}
	return nil
}

type Tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func GenerateTokens(tenantID, userID, role string) (*Tokens, error) {
	privateKey, _ := currentKeys()
	if privateKey == nil {
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
	}).SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}
	refresh, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": userID,
		"ten": tenantID,
		"exp": now.Add(30 * 24 * time.Hour).Unix(),
		"jti": fmt.Sprintf("r-%s-%d", userID, now.UnixNano()),
	}).SignedString(privateKey)
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
	privateKey, _ := currentKeys()
	if privateKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	if refreshTTL <= 0 {
		return nil, errors.New("auth: refresh token TTL must be positive")
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
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
	if tenantID, ok := claims["ten"]; ok {
		refreshClaims["ten"] = tenantID
	}

	refresh, err := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims).SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign refresh: %w", err)
	}
	return &Tokens{Access: access, Refresh: refresh}, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	_, publicKey := currentKeys()
	if publicKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithLeeway(5*time.Second), jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
}

func currentKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	keyMu.RLock()
	defer keyMu.RUnlock()
	return signKey, verifyKey
}
