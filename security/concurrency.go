package security

import (
	"context"
	"sync/atomic"

	"github.com/nexssp/kernel/action"
)

// Global Limiter - useful for completely bounding resource exhaustion across ALL registered actions.
func NewConcurrencyLimiter(limit int32) action.AnyAction {
	var count atomic.Int32

	return action.New[any, any]("plugin.concurrency", nil).
		AnyHook(action.AnyHook{
			Before: func(ctx context.Context, _ any, _ *action.Meta) (context.Context, error) {
				if count.Add(1) > limit {
					count.Add(-1)
					return ctx, action.ErrConcurrencyLimit
				}
				return ctx, nil
			},
			After: func(_ context.Context, _, _ any, _ error, _ *action.Meta) {
				count.Add(-1)
			},
		}).
		Build()
}
