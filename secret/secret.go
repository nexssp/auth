// Package secret wraps sensitive strings to prevent accidental logging or serialization.
package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrSecretNotFound    = errors.New("secret not found in environment or /run/secrets/")
	ErrInvalidSecretName = errors.New("invalid secret name")
)

const runDir = string(filepath.Separator) + "run"

// String wraps a sensitive value. Use Unwrap() to access the actual value.
type String string

func (s String) Unwrap() string { return string(s) }

// String implements fmt.Stringer — never reveals the value in logs.
func (s String) String() string {
	if s == "" {
		return ""
	}
	return "********"
}

// MarshalJSON prevents secrets from leaking in API responses.
func (s String) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return json.Marshal("********")
}

// UnmarshalJSON allows secrets to be loaded from config files / payloads.
func (s *String) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = String(v)
	return nil
}

// Resolve looks for the secret value in a context-aware manner.
func Resolve(ctx context.Context, key string) (String, error) {
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("resolution canceled: %w", ctx.Err())
	default:
		if !validSecretName(key) {
			return "", fmt.Errorf("%w: %q", ErrInvalidSecretName, key)
		}
		if val := os.Getenv(key); val != "" {
			return String(val), nil
		}

		paths := []string{
			filepath.Join(runDir, "secrets", strings.ToLower(key)),
			filepath.Join(runDir, "secrets", key),
		}

		for _, p := range paths {
			if data, err := os.ReadFile(p); err == nil {
				return String(strings.TrimSpace(string(data))), nil
			}
		}

		return "", fmt.Errorf("%w: %s", ErrSecretNotFound, key)
	}
}

func validSecretName(key string) bool {
	if key == "" || key == "." || key == ".." {
		return false
	}
	for _, char := range key {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' {
			continue
		}
		return false
	}
	return true
}
