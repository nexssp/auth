package crypto_test

import (
	"bytes"
	"testing"

	"github.com/nexssp/auth/crypto"
)

func TestEnvelope_TenantIsolation(t *testing.T) {
	t.Parallel()

	env, err := crypto.NewEnvelope("super-secure-master-key-32bytes!")
	if err != nil {
		t.Fatalf("failed to create envelope: %v", err)
	}

	plaintext := []byte("highly sensitive PII data")

	// 1. Encrypt for Tenant A
	cipherA, err := env.EncryptForTenant("tenant_A", plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// 2. Try to decrypt with Tenant B's derived key (Must Fail!)
	_, err = env.DecryptForTenant("tenant_B", cipherA)
	if err == nil {
		t.Fatal("security breach: Tenant B successfully decrypted Tenant A's data")
	}

	// 3. Decrypt with Tenant A's derived key (Must Succeed)
	decrypted, err := env.DecryptForTenant("tenant_A", cipherA)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: expected %q, got %q", plaintext, decrypted)
	}
}
