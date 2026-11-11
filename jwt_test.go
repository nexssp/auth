package auth_test

import (
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
