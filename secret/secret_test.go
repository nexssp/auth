package secret_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nexssp/auth/secret"
)

type Config struct {
	Password secret.String `json:"password"`
}

func TestSecretString_Masking(t *testing.T) {
	t.Parallel()

	s := secret.String("my-super-secret-password")

	// Stringer interface should mask
	if s.String() != "********" {
		t.Errorf("expected masked string, got %s", s.String())
	}

	// Unwrap should reveal
	if s.Unwrap() != "my-super-secret-password" {
		t.Errorf("expected real value, got %s", s.Unwrap())
	}

	// JSON Marshal should mask
	cfg := Config{Password: s}
	// #nosec G117 -- this test verifies that password values are masked during JSON serialization.
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"password":"********"}` {
		t.Errorf("expected JSON to be masked, got %s", string(b))
	}
}

func TestResolve_Env(t *testing.T) {
	t.Setenv("TEST_SECRET_RESOLVE", "hello-world")

	s, err := secret.Resolve(context.Background(), "TEST_SECRET_RESOLVE")
	if err != nil {
		t.Fatalf("expected to resolve from env, got error: %v", err)
	}
	if s.Unwrap() != "hello-world" {
		t.Errorf("expected hello-world, got %s", s.Unwrap())
	}
}
