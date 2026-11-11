package dlock

import (
	"context"
	"log/slog"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
)

// ErrLocked is returned when another instance is already processing the task.
var ErrLocked = xerr.Conflict("resource is currently locked by another instance")

// Mutex defines a distributed lock interface (e.g., Redis, NATS, Postgres).
type Mutex interface {
	TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Unlock(ctx context.Context, key string) error
}

// Exclusive wraps an action so it only executes if it acquires the lock.
// If the lock is held by another node, it returns ErrLocked immediately (fast fail).
func Exclusive[Req, Res any](m Mutex, ttl time.Duration, keyFn func(Req) string) action.Middleware[Req, Res] {
	return func(next action.Fn[Req, Res]) action.Fn[Req, Res] {
		return func(ctx context.Context, req Req) (res Res, err error) {
			key := keyFn(req)
			if key == "" {
				return next(ctx, req)
			}

			acquired, err := m.TryLock(ctx, key, ttl)
			if err != nil {
				return res, xerr.Unavailable("failed to acquire distributed lock", err)
			}
			if !acquired {
				return res, ErrLocked
			}

			// Ensure unlock runs even if the context gets canceled or action panics.
			defer func() {
				if uerr := m.Unlock(context.WithoutCancel(ctx), key); uerr != nil {
					if err == nil {
						err = xerr.Unavailable("failed to release distributed lock", uerr)
					} else {
						// Keep the original error; surface the cleanup failure as a log.
						slog.Warn("dlock: failed to release lock", "key", key, "error", uerr)
					}
				}
			}()

			res, err = next(ctx, req)
			return
		}
	}
}
