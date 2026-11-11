package auth

import (
	"encoding/hex"
	"testing"
)

func TestNewResetTokenMatchesPHPFormatAndDigest(t *testing.T) {
	token, err := NewResetToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token.Value) != 64 {
		t.Fatalf("reset token length = %d, want 64", len(token.Value))
	}
	if _, err := hex.DecodeString(token.Value); err != nil {
		t.Fatalf("reset token is not hexadecimal: %v", err)
	}
	if token.Digest != TokenDigest(token.Value) || token.Digest == token.Value {
		t.Fatalf("reset token digest = %q, does not match digest-only expectation", token.Digest)
	}
}

func TestNewOpaqueTokenMatchesDesktopBearerFormat(t *testing.T) {
	token, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token.Value) != 43 || token.Digest != TokenDigest(token.Value) {
		t.Fatalf("opaque token = %#v, want 43-character value and matching digest", token)
	}
	if token.Value == token.Digest {
		t.Fatal("opaque token plaintext must differ from its stored digest")
	}
}

func TestNewStateTokenAndPKCEHelpers(t *testing.T) {
	state, err := NewStateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 64 {
		t.Fatalf("state length = %d, want 64", len(state))
	}
	if _, err := hex.DecodeString(state); err != nil {
		t.Fatalf("state token is not hexadecimal: %v", err)
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("PKCEChallenge() = %q, want RFC 7636 S256 vector", challenge)
	}
	if _, err := PKCEChallenge(verifier + "!"); err == nil {
		t.Fatal("PKCEChallenge() accepted an invalid character")
	}
}

func TestNewPKCEVerifierUsesVerifierLength(t *testing.T) {
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) != 43 {
		t.Fatalf("verifier length = %d, want 43", len(verifier))
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		t.Fatalf("generated verifier was rejected: %v", err)
	}
}
