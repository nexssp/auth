package crypto

import (
	"encoding/base64"
	"os"
	"testing"
)

// TestMain sets the cryptokey before any test runs.
func TestMain(m *testing.M) {
	os.Setenv("NEXSS_CRYPTO_KEY", "test-super-secret-key-1234567890")
	code := m.Run()
	os.Exit(code)
}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Normal string", "Hello InvoicerX 2026"},
		{"Special characters", "!@#$%^&*()_+~`|}{[]:;?><,./"},
		{"Long string", "This is a much longer string to ensure that the AES-GCM implementation handles varying lengths correctly without padding issues."},
		{"Empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptString(tt.input)
			if err != nil {
				t.Fatalf("EncryptString() failed: %v", err)
			}

			// Encrypting anything (including empty) must produce a non‑empty ciphertext.
			if encrypted == "" {
				t.Errorf("EncryptString(%q) returned empty ciphertext", tt.input)
				return
			}

			// It must be valid Base64.
			_, err = base64.StdEncoding.DecodeString(encrypted)
			if err != nil {
				t.Errorf("Result is not valid Base64: %v", err)
			}

			// Decrypt must give back the original input.
			decrypted, err := DecryptString(encrypted)
			if err != nil {
				t.Fatalf("DecryptString() failed: %v", err)
			}
			if decrypted != tt.input {
				t.Errorf("Encrypt/Decrypt mismatch: got %q, want %q", decrypted, tt.input)
			}
		})
	}
}

func TestEncryptionRandomness(t *testing.T) {
	input := "Sensitive Data"
	res1, err := EncryptString(input)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	res2, err := EncryptString(input)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	if res1 == res2 {
		t.Error("EncryptString produced identical results; Nonce reuse or lack of randomness detected")
	}
}

func TestIntegrityFailure(t *testing.T) {
	plaintext := "Secret Message"
	encrypted, err := EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	// Decode, flip a bit in the ciphertext, re-encode
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Encrypted data is empty")
	}

	data[len(data)-1] ^= 0xFF // Tamper with the last byte (usually part of the Auth Tag)
	tampered := base64.StdEncoding.EncodeToString(data)

	_, err = DecryptString(tampered)
	if err == nil {
		t.Error("DecryptString should have failed for tampered ciphertext (Auth Failure)")
	}
}

func TestMalformedInputs(t *testing.T) {
	t.Run("Invalid Base64", func(t *testing.T) {
		_, err := DecryptString("Not-Base64-Content!")
		if err == nil {
			t.Error("Expected error for invalid Base64 input")
		}
	})

	t.Run("Short Ciphertext", func(t *testing.T) {
		// Encoded string "short"
		short := base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := DecryptString(short)
		if err == nil {
			t.Error("Expected error for ciphertext shorter than Nonce size")
		}
	})
}

func BenchmarkEncrypt(b *testing.B) {
	data := "Standard payload for benchmarking encryption performance 2026"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptString(data); err != nil {
			b.Fatalf("EncryptString failed: %v", err)
		}
	}
}
