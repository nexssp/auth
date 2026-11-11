package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const tokenEntropyBytes = 32

// OpaqueToken contains a one-time plaintext value and its lowercase SHA-256
// digest. Persist Digest only; reveal Value only to the client that must use it.
type OpaqueToken struct {
	Value  string
	Digest string
}

// NewOpaqueToken creates a 256-bit raw-URL-base64 token suitable for opaque
// authorization codes, bearer tokens, or other host-defined token domains.
func NewOpaqueToken() (OpaqueToken, error) {
	secret := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(secret); err != nil {
		return OpaqueToken{}, fmt.Errorf("generate opaque token: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(secret)
	return OpaqueToken{Value: value, Digest: TokenDigest(value)}, nil
}

// NewHexToken creates a 256-bit lowercase-hex token and its digest. The 64-character
// form can be used for password-reset links or other host-owned one-time tokens.
func NewHexToken() (OpaqueToken, error) {
	secret := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(secret); err != nil {
		return OpaqueToken{}, fmt.Errorf("generate hex token: %w", err)
	}
	value := hex.EncodeToString(secret)
	return OpaqueToken{Value: value, Digest: TokenDigest(value)}, nil
}

// NewResetToken creates a 256-bit lowercase-hex token for password-recovery links.
func NewResetToken() (OpaqueToken, error) {
	return NewHexToken()
}

// TokenDigest returns the lowercase SHA-256 hex digest of the exact token bytes.
func TokenDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// NewPKCEVerifier creates a 32-byte verifier using the unpadded URL-safe
// base64url alphabet for OAuth and desktop handoffs.
func NewPKCEVerifier() (string, error) {
	secret := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// PKCEChallenge returns the S256 challenge for a verifier valid under the
// RFC 7636 43-128 character verifier syntax.
func PKCEChallenge(verifier string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 || strings.Trim(verifier, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" {
		return "", errors.New("invalid PKCE verifier")
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// NewStateToken creates a 256-bit lowercase-hex OAuth or desktop state value.
func NewStateToken() (string, error) {
	secret := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate state token: %w", err)
	}
	return hex.EncodeToString(secret), nil
}
