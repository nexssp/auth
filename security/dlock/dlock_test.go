package dlock_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexssp/auth/security/dlock"
	"github.com/nexssp/kernel/action"
)

type mockMutex struct {
	lockFail bool
	unlocked atomic.Bool
}

func (m *mockMutex) TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if m.lockFail {
		return false, nil
	}
	return true, nil
}

func (m *mockMutex) Unlock(ctx context.Context, key string) error {
	m.unlocked.Store(true)
	return nil
}

func TestExclusive_LockAcquired(t *testing.T) {
	t.Parallel()
	m := &mockMutex{}
	var handlerCalled bool

	act := action.New("test.locked", func(ctx context.Context, req string) (string, error) {
		handlerCalled = true
		return "ok", nil
	}).Use(dlock.Exclusive[string, string](m, time.Minute, func(req string) string { return req })).Build()

	res, err := act.Do(context.Background(), "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "ok" || !handlerCalled {
		t.Fatal("handler not called")
	}
	if !m.unlocked.Load() {
		t.Fatal("lock not released")
	}
}

func TestExclusive_LockFailed(t *testing.T) {
	t.Parallel()
	m := &mockMutex{lockFail: true}

	act := action.New("test.locked.fail", func(ctx context.Context, req string) (string, error) {
		return "ok", nil
	}).Use(dlock.Exclusive[string, string](m, time.Minute, func(req string) string { return req })).Build()

	_, err := act.Do(context.Background(), "my-key")
	if !errors.Is(err, dlock.ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}
