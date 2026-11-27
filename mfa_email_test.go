package auth

import (
	"context"
	"sync"
	"testing"
	"time"
)

type storeWithoutAtomicVerificationConsume struct{ Store }

func TestEmailMFACodeCanBeConsumedOnlyOnce(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "account-1", Email: "mfa@example.test"}
	const code = "123456"
	if err := store.CreateVerificationToken(context.Background(), user.ID, user.ID+":"+code, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	provider := NewEmailMFAProvider(store, nil)

	const attempts = 24
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start
			results <- provider.Verify(context.Background(), user, code)
		})
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("successful verifications = %d, want exactly 1", winners)
	}
}

func TestEmailMFAFailsClosedWithoutAtomicStoreCapability(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "account-2", Email: "mfa@example.test"}
	const code = "654321"
	if err := store.CreateVerificationToken(context.Background(), user.ID, user.ID+":"+code, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	provider := NewEmailMFAProvider(storeWithoutAtomicVerificationConsume{Store: store}, nil)
	if err := provider.Verify(context.Background(), user, code); err == nil {
		t.Fatal("email MFA accepted a code without atomic consumption support")
	}
}
