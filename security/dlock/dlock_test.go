package dlock_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/redis/go-redis/v9"

	"github.com/nexssp/auth/security/dlock"
)

type mockMutex struct {
	lockFail bool
	unlocked atomic.Bool
}

func (m *mockMutex) TryLock(_ context.Context, _ string, _ time.Duration) (bool, error) {
	if m.lockFail {
		return false, nil
	}
	return true, nil
}

func (m *mockMutex) Unlock(_ context.Context, _ string) error {
	m.unlocked.Store(true)
	return nil
}

func TestExclusive_LockAcquired(t *testing.T) {
	t.Parallel()
	m := &mockMutex{}
	var handlerCalled bool

	act := action.New("test.locked", func(_ context.Context, _ string) (string, error) {
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

	act := action.New("test.locked.fail", func(_ context.Context, _ string) (string, error) {
		return "ok", nil
	}).Use(dlock.Exclusive[string, string](m, time.Minute, func(req string) string { return req })).Build()

	_, err := act.Do(context.Background(), "my-key")
	if !errors.Is(err, dlock.ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

type fakeRedisHook struct {
	mu     sync.Mutex
	values map[string]string
}

func (hook *fakeRedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (hook *fakeRedisHook) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		hook.mu.Lock()
		defer hook.mu.Unlock()
		switch cmd.Name() {
		case "set":
			key, value := fmt.Sprint(args[1]), fmt.Sprint(args[2])
			if _, exists := hook.values[key]; exists {
				cmd.SetErr(redis.Nil)
				return nil
			}
			hook.values[key] = value
			status, ok := cmd.(*redis.StatusCmd)
			if !ok {
				return fmt.Errorf("Redis SET returned %T, want *redis.StatusCmd", cmd)
			}
			status.SetVal("OK")
		case "eval":
			key, owner := fmt.Sprint(args[3]), fmt.Sprint(args[4])
			var deleted int64
			if hook.values[key] == owner {
				delete(hook.values, key)
				deleted = 1
			}
			evalCmd, ok := cmd.(*redis.Cmd)
			if !ok {
				return fmt.Errorf("Redis EVAL returned %T, want *redis.Cmd", cmd)
			}
			evalCmd.SetVal(deleted)
		default:
			return fmt.Errorf("unexpected Redis command %q", cmd.Name())
		}
		return nil
	}
}

func (hook *fakeRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestRedisLeaseCannotDeleteSuccessorLock(t *testing.T) {
	hook := &fakeRedisHook{values: make(map[string]string)}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	client.AddHook(hook)
	defer client.Close()

	mutex := dlock.NewRedisMutex(client)
	lease, acquired, err := mutex.TryAcquire(context.Background(), "job", time.Minute)
	if err != nil || !acquired || lease == nil {
		t.Fatalf("TryAcquire() = (%v, %v, %v), want an acquired lease", lease, acquired, err)
	}

	key := "nexss:dlock:job"
	hook.mu.Lock()
	hook.values[key] = "successor-owner"
	hook.mu.Unlock()
	if err := lease.Unlock(context.Background()); err != nil {
		t.Fatalf("stale lease Unlock() error = %v", err)
	}

	hook.mu.Lock()
	defer hook.mu.Unlock()
	if got := hook.values[key]; got != "successor-owner" {
		t.Fatalf("successor lock value = %q, want it to remain held", got)
	}
}
