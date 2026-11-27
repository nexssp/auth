package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

const (
	tokenUseAccess         = "access"
	tokenUseRefresh        = "refresh"
	tokenTypeMFAPreAuth    = "pre-auth"
	tokenTypeTrustedDevice = "trusted_device"
)

func GenerateTokens(tenantID, userID, role string) (*Tokens, error) {
	privateKey, _ := currentKeys()
	if privateKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	now := time.Now()
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":       userID,
		"ten":       tenantID,
		"role":      role,
		"token_use": tokenUseAccess,
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       fmt.Sprintf("a-%s-%d", userID, now.UnixNano()),
	}).SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}
	refresh, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":       userID,
		"ten":       tenantID,
		"token_use": tokenUseRefresh,
		"exp":       now.Add(30 * 24 * time.Hour).Unix(),
		"jti":       fmt.Sprintf("r-%s-%d", userID, now.UnixNano()),
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
	return generateTokensWithRefreshID(claims, refreshTTL, uuid.NewString())
}

func generateTokensWithRefreshID(claims jwt.MapClaims, refreshTTL time.Duration, refreshID string) (*Tokens, error) {
	privateKey, _ := currentKeys()
	if privateKey == nil {
		return nil, errors.New("auth: keys not initialized")
	}
	if refreshTTL <= 0 {
		return nil, errors.New("auth: refresh token TTL must be positive")
	}
	if refreshID == "" {
		return nil, errors.New("auth: refresh token id is required")
	}
	if _, ok := claims["exp"]; !ok || claims["exp"] == nil {
		return nil, errors.New("auth: access token expiration is required")
	}
	accessClaims := make(jwt.MapClaims, len(claims)+1)
	maps.Copy(accessClaims, claims)
	accessClaims["token_use"] = tokenUseAccess
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims).SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access: %w", err)
	}

	refreshClaims := jwt.MapClaims{
		"sub":       claims["sub"],
		"token_use": tokenUseRefresh,
		"exp":       time.Now().Add(refreshTTL).Unix(),
		"jti":       refreshID,
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
	}, jwt.WithLeeway(5*time.Second), jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithExpirationRequired())
}

// VerifyAccessToken verifies a signed, expiring access token. Use this at
// authorization boundaries instead of the purpose-agnostic VerifyToken helper.
func VerifyAccessToken(tokenString string) (*jwt.Token, error) {
	token, err := verifyTokenUse(tokenString, tokenUseAccess)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] == tokenTypeMFAPreAuth || claims["type"] == tokenTypeTrustedDevice {
		return nil, errors.New("auth: invalid token purpose")
	}
	return token, nil
}

// VerifyRefreshToken verifies a signed, expiring refresh token.
func VerifyRefreshToken(tokenString string) (*jwt.Token, error) {
	return verifyTokenUse(tokenString, tokenUseRefresh)
}

func verifyTypedAccessToken(tokenString, wantType string) (*jwt.Token, error) {
	// Legacy MFA credentials predate token_use; permit that omission only for
	// their exact typed purpose, never for ordinary access-token verification.
	token, err := VerifyToken(tokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != wantType {
		return nil, errors.New("auth: invalid token purpose")
	}
	if tokenUse, hasTokenUse := claims["token_use"]; hasTokenUse && tokenUse != tokenUseAccess {
		return nil, errors.New("auth: invalid token purpose")
	}
	return token, nil
}

func verifyTokenUse(tokenString, want string) (*jwt.Token, error) {
	token, err := VerifyToken(tokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["token_use"] != want {
		return nil, errors.New("auth: invalid token purpose")
	}
	return token, nil
}

func currentKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	keyMu.RLock()
	defer keyMu.RUnlock()
	return signKey, verifyKey
}
