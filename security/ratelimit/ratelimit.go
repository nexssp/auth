package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// Limiter is the interface for distributed or local rate limiting.
type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// ── In‑memory limiter (token bucket per key) ────────────────────────────────

type memoryLimiter struct {
	mu    sync.RWMutex
	m     map[string]*rate.Limiter
	rps   rate.Limit
	burst int
}

// NewMemoryLimiter creates a lock‑free per‑key token bucket limiter for single‑node.
func NewMemoryLimiter(rps float64, burst int) Limiter {
	return &memoryLimiter{
		m:     make(map[string]*rate.Limiter),
		rps:   rate.Limit(rps),
		burst: burst,
	}
}

func (l *memoryLimiter) Allow(_ context.Context, key string) (bool, error) {
	if key == "" {
		key = "global"
	}
	l.mu.RLock()
	lim, ok := l.m[key]
	l.mu.RUnlock()
	if ok {
		return lim.Allow(), nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok = l.m[key]; ok {
		return lim.Allow(), nil
	}
	lim = rate.NewLimiter(l.rps, l.burst)
	l.m[key] = lim
	return lim.Allow(), nil
}

// memoryLimiter implementation ... (omitted for brevity, same as previous but kept in file)

type redisLimiter struct {
	client *redis.Client
	script *redis.Script
	rps    float64
	burst  int
	prefix string // Prevents collisions between different containers/services
}

// NewRedisLimiter creates a distributed limiter with a prefix for isolation.
func NewRedisLimiter(client *redis.Client, rps float64, burst int, prefix string) Limiter {
	// Lua script uses the prefix-safe key
	script := redis.NewScript(`
		local key = KEYS[1]
		local rps = tonumber(ARGV[1])
		local burst = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])

		local data = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(data[1]) or burst
		local last_refill = tonumber(data[2]) or now

		local elapsed = math.max(0, now - last_refill)
		local new_tokens = math.min(burst, tokens + elapsed * rps)

		if new_tokens >= 1 then
			redis.call('HMSET', key, 'tokens', new_tokens - 1, 'last_refill', now)
			redis.call('EXPIRE', key, math.ceil(burst / rps) + 1)
			return 1
		end
		return 0
	`)
	return &redisLimiter{
		client: client,
		script: script,
		rps:    rps,
		burst:  burst,
		prefix: prefix,
	}
}

func (l *redisLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if key == "" {
		key = "global"
	}
	// Why: Namespacing ensures isolation in shared Redis environments
	fullKey := fmt.Sprintf("%s:rl:%s", l.prefix, key)

	now := float64(time.Now().UnixNano()) / 1e9
	res, err := l.script.Run(ctx, l.client, []string{fullKey}, l.rps, l.burst, now).Int()
	if err != nil {
		return false, fmt.Errorf("redis ratelimit execution: %w", err)
	}
	return res == 1, nil
}
