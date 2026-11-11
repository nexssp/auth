package security_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nexssp/auth/security"
	"github.com/nexssp/kernel/action"
)

func TestGlobalConcurrencyLimiter(t *testing.T) {
	t.Parallel()

	// Limit to 2 concurrent global requests
	plugin := security.NewConcurrencyLimiter(2)

	// Block the handler until we release it
	block := make(chan struct{})

	act1 := action.New("test.1", func(ctx context.Context, _ struct{}) (string, error) {
		<-block
		return "ok", nil
	}).Add(plugin).Build()

	act2 := action.New("test.2", func(ctx context.Context, _ struct{}) (string, error) {
		<-block
		return "ok", nil
	}).Add(plugin).Build()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	// Fire 3 requests simultaneously across different actions
	fire := func(a *action.BuiltAction[struct{}, string]) {
		wg.Go(func() {
			_, err := a.Do(context.Background(), struct{}{})
			if err != nil {
				errCh <- err
			}
		})
	}

	fire(act1)
	fire(act2)
	time.Sleep(50 * time.Millisecond) // Let them lock

	// 3rd request should fail instantly because global limit is 2
	_, err := act1.Do(context.Background(), struct{}{})
	if !errors.Is(err, action.ErrConcurrencyLimit) {
		t.Fatalf("expected ErrConcurrencyLimit, got %v", err)
	}

	// Release blocked handlers
	close(block)
	wg.Wait()
}
