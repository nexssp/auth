package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

var ErrMasterKeyTooShort = errors.New("crypto: master key secret must be at least 16 bytes")

// Envelope zapewnia szyfrowanie AES-256-GCM z unikalnym kluczem wywodzonym dla każdego najemcy.
type Envelope struct {
	masterKey []byte
}

func NewEnvelope(masterKeySecret string) (*Envelope, error) {
	if len(masterKeySecret) < 16 {
		return nil, ErrMasterKeyTooShort
	}
	hash := sha256.Sum256([]byte(masterKeySecret))
	return &Envelope{masterKey: hash[:]}, nil
}

// DeriveTenantKey generuje unikalny, 256-bitowy klucz DEK (Data Encryption Key) dla danego najemcy.
func (e *Envelope) DeriveTenantKey(tenantID string) []byte {
	return pbkdf2.Key(e.masterKey, []byte("tenant_salt:"+tenantID), 10000, 32, sha256.New)
}

// EncryptForTenant szyfruje dane przy użyciu klucza izolowanego dla konkretnego najemcy.
func (e *Envelope) EncryptForTenant(tenantID string, plaintext []byte) ([]byte, error) {
	key := e.DeriveTenantKey(tenantID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptForTenant odszyfrowuje dane przy użyciu klucza najemcy.
func (e *Envelope) DecryptForTenant(tenantID string, ciphertext []byte) ([]byte, error) {
	key := e.DeriveTenantKey(tenantID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope decrypt: %w", err)
	}

	return plaintext, nil
}
