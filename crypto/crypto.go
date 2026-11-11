package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	ErrCiphertextTooShort       = errors.New("ciphertext too short")
	ErrEncryptionKeyUnavailable = errors.New("NEXSS_CRYPTO_KEY is not configured")
	ErrInvalidEncryptionKey     = errors.New("NEXSS_CRYPTO_KEY must encode exactly 32 bytes")
)

// getKey reads NEXSS_CRYPTO_KEY when called. The key must be exactly 32 raw
// bytes, 64 hexadecimal characters, or a standard/raw Base64 encoding of 32
// bytes. Missing or malformed keys fail closed; no development fallback is used.
func getKey() ([]byte, error) {
	configured, ok := os.LookupEnv("NEXSS_CRYPTO_KEY")
	if !ok || configured == "" {
		return nil, ErrEncryptionKeyUnavailable
	}
	if len(configured) == 32 {
		return []byte(configured), nil
	}
	if len(configured) == 64 {
		key, err := hex.DecodeString(configured)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		key, err := encoding.DecodeString(configured)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, ErrInvalidEncryptionKey
}

// EncryptString encrypts a plaintext string with AES-256-GCM and returns a
// Base64-encoded nonce and ciphertext. Set NEXSS_CRYPTO_KEY before use.
func EncryptString(plaintext string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", fmt.Errorf("crypto key: %w", err)
	}
	block, err := aes.NewCipher(key)
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

// DecryptString decrypts a Base64-encoded value produced by EncryptString.
func DecryptString(ciphertext string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", fmt.Errorf("crypto key: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}

	block, err := aes.NewCipher(key)
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
