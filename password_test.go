package auth

import (
	"errors"
	"strings"
	"testing"
)

// Generated with PHP 8.3 password_hash("nexss-php-bcrypt-fixture", PASSWORD_DEFAULT).
const phpBcryptFixture = "$2y$10$RxbO7Z7a7oO6SGNPxh5RIepIDqB.DZ5C120FRsbSWxwEvmtFHX3M6"

func TestVerifyPasswordAcceptsExistingPHPBcryptHash(t *testing.T) {
	if err := VerifyPassword("nexss-php-bcrypt-fixture", phpBcryptFixture); err != nil {
		t.Fatalf("VerifyPassword() rejected PHP $2y$ hash: %v", err)
	}

	legacyPrefix := "$2a$" + strings.TrimPrefix(phpBcryptFixture, "$2y$")
	if err := VerifyPassword("nexss-php-bcrypt-fixture", legacyPrefix); err != nil {
		t.Fatalf("VerifyPassword() rejected compatible $2a$ hash: %v", err)
	}
}

func TestVerifyPasswordReportsMismatchAndUnsupportedHash(t *testing.T) {
	if err := VerifyPassword("wrong password", phpBcryptFixture); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("VerifyPassword() error = %v, want ErrPasswordMismatch", err)
	}
	if err := VerifyPassword("password", "$argon2id$v=19$m=65536,t=3,p=1$not-a-hash"); !errors.Is(err, ErrUnsupportedPasswordHash) {
		t.Fatalf("VerifyPassword() error = %v, want ErrUnsupportedPasswordHash", err)
	}
}

func TestVerifyPasswordRejectsMalformedBcryptHash(t *testing.T) {
	if err := VerifyPassword("password", "$2y$10$short"); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("VerifyPassword() error = %v, want ErrInvalidPasswordHash", err)
	}
}
