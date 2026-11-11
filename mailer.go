package auth

import (
	"context"
	"log/slog"
)

// NoopEmailer acts as a null-sink for testing/local setups. Logs outputs directly.
type NoopEmailer struct{}

func (NoopEmailer) Send(ctx context.Context, to, subject, body string) error {
	slog.InfoContext(ctx, "mock_email_sent",
		"to", to,
		"subject", subject,
		"body", body,
	)
	return nil
}
