package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidOneTimeToken covers an unknown, expired, or already-consumed token.
	ErrInvalidOneTimeToken = errors.New("invalid, expired, or consumed one-time token")
	// ErrOneTimeTokenStoreUnavailable indicates that no host store was supplied.
	ErrOneTimeTokenStoreUnavailable = errors.New("one-time token store is unavailable")
)

// OneTimeTokenStore is the host persistence seam. Bind each instance to a
// host-owned token domain (for example, reset or email verification) and persist
// only the digest. ConsumeOneTimeToken must, in one transaction/atomic operation,
// locate a token whose expiry is strictly after now, claim/delete it, call apply
// with its subject, and commit only if apply succeeds. The callback should make
// the host-side state change using the transaction represented by callbackCtx.
// Return ErrInvalidOneTimeToken when no eligible token exists.
//
// This contract supports atomic reset completion and email-verification marking
// without deciding account policy or introducing an application database here.
type OneTimeTokenStore interface {
	InsertOneTimeToken(ctx context.Context, digest, subject string, expiresAt time.Time) error
	ConsumeOneTimeToken(ctx context.Context, digest string, now time.Time, apply func(callbackCtx context.Context, subject string) error) error
}

// OneTimeTokenRevoker is an optional capability for removing a token when its
// email notification failed. Host stores may implement it alongside the atomic
// consume contract.
type OneTimeTokenRevoker interface {
	RevokeOneTimeToken(ctx context.Context, digest string) error
}

// OneTimeTokens applies storage-neutral one-time-token mechanics over a
// host-selected store. A store instance should be scoped to one token domain.
type OneTimeTokens struct {
	Store OneTimeTokenStore
}

// Issue creates a random 64-character lowercase-hex token and stores only its
// digest. The host chooses the token domain, expiry, and any replacement policy.
func (tokens OneTimeTokens) Issue(ctx context.Context, subject string, expiresAt time.Time) (string, error) {
	if tokens.Store == nil {
		return "", ErrOneTimeTokenStoreUnavailable
	}
	if subject == "" || expiresAt.IsZero() {
		return "", errors.New("one-time token subject and expiry are required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token, err := NewHexToken()
	if err != nil {
		return "", err
	}
	if err := tokens.Store.InsertOneTimeToken(ctx, token.Digest, subject, expiresAt); err != nil {
		return "", fmt.Errorf("store one-time token: %w", err)
	}
	return token.Value, nil
}

// Consume validates the 64-character lowercase-hex value and delegates its
// single-use consume plus apply callback to the store's atomic transaction.
func (tokens OneTimeTokens) Consume(ctx context.Context, value string, now time.Time, apply func(callbackCtx context.Context, subject string) error) error {
	if tokens.Store == nil {
		return ErrOneTimeTokenStoreUnavailable
	}
	if len(value) != 64 || !isLowerHex(value) || now.IsZero() || apply == nil {
		return ErrInvalidOneTimeToken
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tokens.Store.ConsumeOneTimeToken(ctx, TokenDigest(value), now, apply); err != nil {
		if errors.Is(err, ErrInvalidOneTimeToken) {
			return ErrInvalidOneTimeToken
		}
		return fmt.Errorf("consume one-time token: %w", err)
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
