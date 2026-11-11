package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/nexssp/auth"
)

func TestJWT_SigningAndVerification(t *testing.T) {
	t.Parallel()

	// 1. Initialize RSA keys
	if err := auth.InitTempKeys(); err != nil {
		t.Fatalf("failed to initialize temp RSA keys: %v", err)
	}

	// 2. Generate Tokens
	tokens, err := auth.GenerateTokens("tenant-alpha", "user-123", "admin")
	if err != nil {
		t.Fatalf("failed to generate tokens: %v", err)
	}

	if tokens.Access == "" || tokens.Refresh == "" {
		t.Fatal("expected non-empty access and refresh tokens")
	}

	// 3. Verify Access Token
	parsedToken, err := auth.VerifyToken(tokens.Access)
	if err != nil || !parsedToken.Valid {
		t.Fatalf("token verification failed: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to parse map claims")
	}

	if claims["sub"] != "user-123" || claims["ten"] != "tenant-alpha" || claims["role"] != "admin" {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// 4. Reject Tampered Token
	tamperedToken := tokens.Access + "tampered"
	_, err = auth.VerifyToken(tamperedToken)
	if err == nil {
		t.Fatal("expected verification error for tampered token")
	}
}

func TestJWT_CustomClaims(t *testing.T) {
	t.Parallel()

	_ = auth.InitTempKeys()

	customClaims := jwt.MapClaims{
		"sub":   "usr_custom_555",
		"ten":   "tenant_beta",
		"roles": []string{"operator", "billing"},
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	}

	tokens, err := auth.GenerateTokensWithClaims(customClaims)
	if err != nil {
		t.Fatalf("failed to generate tokens with custom claims: %v", err)
	}

	parsed, err := auth.VerifyToken(tokens.Access)
	if err != nil || !parsed.Valid {
		t.Fatalf("failed to verify custom claims token: %v", err)
	}
}

func TestJWTRejectsMismatchedKeysAndNonRS256Algorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})
	otherPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&otherKey.PublicKey)})
	if err := auth.InitKeys(privatePEM, publicPEM); err != nil {
		t.Fatalf("InitKeys rejected matching 2048-bit keys: %v", err)
	}
	if err := auth.InitKeys(privatePEM, otherPublicPEM); err == nil {
		t.Fatal("InitKeys accepted mismatched RSA key pair")
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims{
		"sub": "user-123", "exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.VerifyToken(token); err == nil {
		t.Fatal("VerifyToken accepted an RS384 token; only RS256 is allowed")
	}
}
