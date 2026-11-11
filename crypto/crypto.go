package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

var ErrCiphertextTooShort = errors.New("ciphertext too short")

// Key holds the encryption key once initialized.
var (
	key     []byte
	keyOnce sync.Once
)

// getKey returns the encryption key, reading NEXSS_CRYPTO_KEY from the environment
// on first access. This runs after godotenv.Load() so .env files are effective.
func getKey() []byte {
	keyOnce.Do(func() {
		k := os.Getenv("NEXSS_CRYPTO_KEY")
		if k == "" {
			slog.Warn("NEXSS_CRYPTO_KEY not set – using ephemeral dev key (secrets invalid after restart)")
			k = "0123456789abcdef0123456789abcdef" // 32‑byte fallback for local dev only
		}
		// Ensure the key is exactly 32 bytes for AES-256.
		keyBytes := []byte(k)
		if len(keyBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded, keyBytes)
			keyBytes = padded
		} else if len(keyBytes) > 32 {
			keyBytes = keyBytes[:32]
		}
		key = keyBytes
	})
	return key
}

// EncryptString encrypts a plaintext string and returns a base64‑encoded ciphertext.
func EncryptString(plaintext string) (string, error) {
	k := getKey()

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a base64‑encoded ciphertext produced by EncryptString.
func DecryptString(ciphertext string) (string, error) {
	k := getKey()

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", ErrCiphertextTooShort
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}
