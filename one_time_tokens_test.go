package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeOneTimeToken struct {
	subject   string
	expiresAt time.Time
}

type fakeOneTimeTokenStore struct {
	mu     sync.Mutex
	tokens map[string]fakeOneTimeToken
}

func newFakeOneTimeTokenStore() *fakeOneTimeTokenStore {
	return &fakeOneTimeTokenStore{tokens: make(map[string]fakeOneTimeToken)}
}

func (store *fakeOneTimeTokenStore) InsertOneTimeToken(ctx context.Context, digest, subject string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.tokens[digest] = fakeOneTimeToken{subject: subject, expiresAt: expiresAt}
	return nil
}

func (store *fakeOneTimeTokenStore) ConsumeOneTimeToken(ctx context.Context, digest string, now time.Time, apply func(context.Context, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	token, ok := store.tokens[digest]
	if !ok || !token.expiresAt.After(now) {
		return ErrInvalidOneTimeToken
	}
	if err := apply(ctx, token.subject); err != nil {
		return err
	}
	delete(store.tokens, digest)
	return nil
}

var _ OneTimeTokenStore = (*fakeOneTimeTokenStore)(nil)

func TestOneTimeTokensIssueStoresDigestAndConsumeOnce(t *testing.T) {
	store := newFakeOneTimeTokenStore()
	service := OneTimeTokens{Store: store}
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	value, err := service.Issue(context.Background(), "account-ref-17", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	digest := TokenDigest(value)
	store.mu.Lock()
	stored, ok := store.tokens[digest]
	_, storedAsPlaintext := store.tokens[value]
	store.mu.Unlock()
	if !ok || stored.subject != "account-ref-17" || storedAsPlaintext {
		t.Fatalf("fake store did not retain only the digest: %#v", store.tokens)
	}

	var appliedSubject string
	if err := service.Consume(context.Background(), value, now, func(_ context.Context, subject string) error {
		appliedSubject = subject
		return nil
	}); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if appliedSubject != "account-ref-17" {
		t.Fatalf("applied subject = %q, want account-ref-17", appliedSubject)
	}
	if err := service.Consume(context.Background(), value, now, func(context.Context, string) error {
		t.Fatal("replayed token invoked apply callback")
		return nil
	}); !errors.Is(err, ErrInvalidOneTimeToken) {
		t.Fatalf("replayed Consume() error = %v, want ErrInvalidOneTimeToken", err)
	}
}

func TestOneTimeTokensRejectExpiredAndMalformedValues(t *testing.T) {
	store := newFakeOneTimeTokenStore()
	service := OneTimeTokens{Store: store}
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	value, err := service.Issue(context.Background(), "account-ref", now)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	apply := func(context.Context, string) error { called = true; return nil }
	if err := service.Consume(context.Background(), value, now, apply); !errors.Is(err, ErrInvalidOneTimeToken) {
		t.Fatalf("expired Consume() error = %v, want ErrInvalidOneTimeToken", err)
	}
	if called {
		t.Fatal("expired token invoked apply callback")
	}
	if err := service.Consume(context.Background(), "not-a-token", now, apply); !errors.Is(err, ErrInvalidOneTimeToken) {
		t.Fatalf("malformed Consume() error = %v, want ErrInvalidOneTimeToken", err)
	}
	if called {
		t.Fatal("malformed token invoked apply callback")
	}
}

func TestOneTimeTokenRemainsAvailableWhenApplyFails(t *testing.T) {
	store := newFakeOneTimeTokenStore()
	service := OneTimeTokens{Store: store}
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	value, err := service.Issue(context.Background(), "account-ref", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	applyErr := errors.New("host state update failed")
	if err := service.Consume(context.Background(), value, now, func(context.Context, string) error { return applyErr }); !errors.Is(err, applyErr) {
		t.Fatalf("Consume() error = %v, want callback error", err)
	}
	if err := service.Consume(context.Background(), value, now, func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("token was consumed despite callback failure: %v", err)
	}
}

func TestOneTimeTokenConcurrentConsumeHasOneWinner(t *testing.T) {
	store := newFakeOneTimeTokenStore()
	service := OneTimeTokens{Store: store}
	now := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	value, err := service.Issue(context.Background(), "account-ref", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 24
	start := make(chan struct{})
	results := make(chan error, attempts)
	var applied atomic.Int32
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			results <- service.Consume(context.Background(), value, now, func(context.Context, string) error {
				applied.Add(1)
				return nil
			})
		}()
	}
	close(start)

	winners := 0
	invalid := 0
	for i := 0; i < attempts; i++ {
		err := <-results
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrInvalidOneTimeToken):
			invalid++
		default:
			t.Fatalf("Consume() error = %v, want success or ErrInvalidOneTimeToken", err)
		}
	}
	if winners != 1 || invalid != attempts-1 || applied.Load() != 1 {
		t.Fatalf("concurrent consumes: winners=%d invalid=%d callbacks=%d, want 1/%d/1", winners, invalid, applied.Load(), attempts-1)
	}
}

func TestOneTimeTokensRequireStoreAndHonorCanceledContext(t *testing.T) {
	if _, err := (OneTimeTokens{}).Issue(context.Background(), "subject", time.Now().Add(time.Hour)); !errors.Is(err, ErrOneTimeTokenStoreUnavailable) {
		t.Fatalf("Issue() without store error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := OneTimeTokens{Store: newFakeOneTimeTokenStore()}
	if _, err := service.Issue(ctx, "subject", time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Issue() with canceled context error = %v", err)
	}
}
