package auth

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrPasswordMismatch means the supplied password does not match the stored hash.
	ErrPasswordMismatch = errors.New("password does not match")
	// ErrUnsupportedPasswordHash means the stored hash algorithm is not supported here.
	ErrUnsupportedPasswordHash = errors.New("unsupported password hash")
	// ErrInvalidPasswordHash means a recognized bcrypt hash is malformed or invalid.
	ErrInvalidPasswordHash = errors.New("invalid password hash")
)

// HashPassword creates a bcrypt hash. Length and account policy belong to the
// caller.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate bcrypt hash: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword compares a candidate against a supported bcrypt hash. It accepts
// $2y$ and $2a$ encodings, and does not create hashes or apply account policy.
func VerifyPassword(password, encodedHash string) error {
	if !strings.HasPrefix(encodedHash, "$2y$") && !strings.HasPrefix(encodedHash, "$2a$") {
		return ErrUnsupportedPasswordHash
	}
	if len(encodedHash) != 60 {
		return ErrInvalidPasswordHash
	}
	if _, err := bcrypt.Cost([]byte(encodedHash)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPasswordHash, err)
	}

	err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrPasswordMismatch
	}
	if err != nil {
		return fmt.Errorf("compare bcrypt hash: %w", err)
	}
	return nil
}
