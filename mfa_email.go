package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/nexssp/kernel/xerr"
)

// EmailMFAProvider to domyślna implementacja 2FA wysyłająca kod na e-mail.
type EmailMFAProvider struct {
	store   Store
	emailer Emailer
}

func NewEmailMFAProvider(store Store, emailer Emailer) *EmailMFAProvider {
	return &EmailMFAProvider{store: store, emailer: emailer}
}

func (p *EmailMFAProvider) ID() string   { return "email" }
func (p *EmailMFAProvider) Name() string { return "Wiadomość E-mail" }
func (p *EmailMFAProvider) Type() string {
	return "code" // UI powinno wyrenderować 6-cyfrowy input
}

func (p *EmailMFAProvider) Challenge(ctx context.Context, user *User) (string, error) {
	// 1. Generowanie 6 cyfr (kryptograficznie bezpieczne)
	max := big.NewInt(1000000)
	n, _ := rand.Int(rand.Reader, max)
	code := fmt.Sprintf("%06d", n.Int64())

	// 2. Zabezpieczenie przed kolizją (łączymy ID usera z kodem)
	dbToken := user.ID + ":" + code
	exp := time.Now().Add(5 * time.Minute)
	if err := p.store.CreateVerificationToken(ctx, user.ID, dbToken, exp); err != nil {
		return "", xerr.Database("Błąd generowania sesji 2FA", err)
	}

	// 3. Wysyłka asynchroniczna
	if tmplMailer, ok := p.emailer.(interface {
		SendTemplate(context.Context, string, string, string, any) error
	}); ok {
		go tmplMailer.SendTemplate(context.WithoutCancel(ctx), user.Email, "Twój kod logowania", "auth", map[string]string{
			"Title":      "Logowanie 2FA",
			"Message":    "Twój jednorazowy kod logowania to: " + code,
			"ButtonText": code,
			"TTL":        "5 minut",
		})
	} else {
		go p.emailer.Send(context.WithoutCancel(ctx), user.Email, "Kod logowania", "Twój kod to: "+code)
	}

	// Maskowanie maila dla bezpieczeństwa (j***e@example.com)
	return maskEmail(user.Email), nil
}

func (p *EmailMFAProvider) Verify(ctx context.Context, user *User, input string) error {
	dbToken := user.ID + ":" + input
	tokenUserID, err := p.store.GetVerificationToken(ctx, dbToken)
	if err != nil || tokenUserID != user.ID {
		return xerr.Unauthorized("Nieprawidłowy lub wygasły kod.")
	}

	// Sukces: Spalamy kod (One-Time Use)
	_ = p.store.DeleteVerificationToken(ctx, dbToken)
	return nil
}

func maskEmail(email string) string {
	if len(email) < 5 {
		return email
	}
	return email[0:1] + "***" + email[len(email)-4:]
}
