package auth

import (
	"context"
	"errors"
)

var errAtomicVerificationTokenConsumptionUnavailable = errors.New("auth: store does not support atomic verification-token consumption")

func consumeVerificationToken(ctx context.Context, store Store, userID, token string) error {
	consumer, ok := store.(VerificationTokenConsumer)
	if !ok {
		return errAtomicVerificationTokenConsumptionUnavailable
	}
	return consumer.ConsumeVerificationToken(ctx, userID, token)
}
