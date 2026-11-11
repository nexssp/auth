package fail2ban

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/redis/go-redis/v9"
)

// Protector prevents brute-force attacks.
type Protector interface {
	Check(ctx context.Context, key string) error
	RecordFailure(ctx context.Context, key string)
	RecordSuccess(ctx context.Context, key string)
}

// Fail2Ban middleware.
func Fail2Ban[Req, Res any](p Protector, keyFn func(ctx context.Context, req Req) string) action.Middleware[Req, Res] {
	return func(next action.Fn[Req, Res]) action.Fn[Req, Res] {
		return func(ctx context.Context, req Req) (Res, error) {
			var zero Res
			key := keyFn(ctx, req)
			if key == "" {
				key = xctx.ClientIPFrom(ctx)
			}
			if err := p.Check(ctx, key); err != nil {
				return zero, err
			}
			res, err := next(ctx, req)
			if err != nil && xerr.KindFrom(err) == xerr.KindUnauthorized {
				p.RecordFailure(context.WithoutCancel(ctx), key)
			} else if err == nil {
				p.RecordSuccess(context.WithoutCancel(ctx), key)
			}
			return res, err
		}
	}
}

// ── Redis Implementation (For Clusters) ──────────────────────────────────────

type RedisProtector struct {
	client   *redis.Client
	prefix   string
	maxFails int
	window   time.Duration
	lockout  time.Duration
}

func NewRedisProtector(client *redis.Client, prefix string, maxFails int, window, lockout time.Duration) Protector {
	return &RedisProtector{client: client, prefix: prefix, maxFails: maxFails, window: window, lockout: lockout}
}

func (r *RedisProtector) Check(ctx context.Context, key string) error {
	lockKey := r.prefix + ":lock:" + key
	ttl := r.client.PTTL(ctx, lockKey).Val()
	if ttl > 0 {
		return xerr.TooManyRequests(fmt.Sprintf("Too many failed attempts. IP locked for %d minutes.", int(ttl.Minutes())+1))
	}
	return nil
}

func (r *RedisProtector) RecordFailure(ctx context.Context, key string) {
	failKey := r.prefix + ":fail:" + key
	lockKey := r.prefix + ":lock:" + key

	// Atomic increment
	count := r.client.Incr(ctx, failKey).Val()

	// If it's the first failure, set the window expiration
	if count == 1 {
		r.client.PExpire(ctx, failKey, r.window)
	}

	// Trigger penalty box
	if count >= int64(r.maxFails) {
		r.client.Set(ctx, lockKey, 1, r.lockout)
		r.client.Del(ctx, failKey) // Reset counter once locked
	}
}

func (r *RedisProtector) RecordSuccess(ctx context.Context, key string) {
	r.client.Del(ctx, r.prefix+":fail:"+key)
	r.client.Del(ctx, r.prefix+":lock:"+key)
}

// ── Memory Implementation (For Single-Node / Dev) ───────────────────────────

type memEntry struct {
	fails       int
	firstFail   time.Time
	lockedUntil time.Time
}

type MemoryProtector struct {
	mu       sync.RWMutex
	entries  map[string]*memEntry
	maxFails int
	window   time.Duration
	lockout  time.Duration
}

func NewMemoryProtector(maxFails int, window, lockout time.Duration) Protector {
	p := &MemoryProtector{
		entries:  make(map[string]*memEntry),
		maxFails: maxFails,
		window:   window,
		lockout:  lockout,
	}
	go p.janitor()
	return p
}

func (m *MemoryProtector) Check(_ context.Context, key string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if e, ok := m.entries[key]; ok {
		if time.Now().Before(e.lockedUntil) {
			mins := int(time.Until(e.lockedUntil).Minutes()) + 1
			return xerr.TooManyRequests(fmt.Sprintf("Too many failed attempts. IP locked for %d minutes.", mins))
		}
	}
	return nil
}

func (m *MemoryProtector) RecordFailure(_ context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	e, ok := m.entries[key]
	if !ok || now.After(e.firstFail.Add(m.window)) {
		// New tracking window
		m.entries[key] = &memEntry{fails: 1, firstFail: now}
		return
	}

	e.fails++
	if e.fails >= m.maxFails {
		e.lockedUntil = now.Add(m.lockout)
		e.fails = 0 // Reset failures because they are now locked
	}
}

func (m *MemoryProtector) RecordSuccess(_ context.Context, key string) {
	m.mu.Lock()
	delete(m.entries, key)
	m.mu.Unlock()
}

func (m *MemoryProtector) janitor() {
	ticker := time.NewTicker(m.window)
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for k, e := range m.entries {
			if now.After(e.lockedUntil) && now.After(e.firstFail.Add(m.window)) {
				delete(m.entries, k)
			}
		}
		m.mu.Unlock()
	}
}
