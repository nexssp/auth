package dlock

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const compareAndDeleteLockScript = `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`

// RedisMutex implements an ownership-aware distributed lock using Redis SET NX.
type RedisMutex struct {
	client       *redis.Client
	prefix       string
	legacyMu     sync.Mutex
	legacyLeases map[string]Lease
}

func NewRedisMutex(client *redis.Client) *RedisMutex {
	return &RedisMutex{client: client, prefix: "nexss:dlock:", legacyLeases: make(map[string]Lease)}
}

func (m *RedisMutex) TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	m.legacyMu.Lock()
	defer m.legacyMu.Unlock()
	if _, held := m.legacyLeases[key]; held {
		return false, nil
	}
	lease, acquired, err := m.TryAcquire(ctx, key, ttl)
	if acquired {
		m.legacyLeases[key] = lease
	}
	return acquired, err
}

func (m *RedisMutex) TryAcquire(ctx context.Context, key string, ttl time.Duration) (Lease, bool, error) {
	if m == nil || m.client == nil || key == "" || ttl <= 0 {
		return nil, false, errors.New("dlock: Redis client, key, and positive TTL are required")
	}
	owner := uuid.NewString()
	redisKey := m.prefix + key
	res, err := m.client.SetArgs(ctx, redisKey, owner, redis.SetArgs{
		Mode: "NX",
		TTL:  ttl,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if res != "OK" {
		return nil, false, nil
	}
	return &redisLease{client: m.client, key: redisKey, owner: owner}, true, nil
}

func (m *RedisMutex) Unlock(ctx context.Context, key string) error {
	m.legacyMu.Lock()
	lease := m.legacyLeases[key]
	delete(m.legacyLeases, key)
	m.legacyMu.Unlock()
	if lease == nil {
		return nil
	}
	return lease.Unlock(ctx)
}

type redisLease struct {
	client *redis.Client
	key    string
	owner  string
}

func (lease *redisLease) Unlock(ctx context.Context) error {
	return lease.client.Eval(ctx, compareAndDeleteLockScript, []string{lease.key}, lease.owner).Err()
}

var _ LeaseMutex = (*RedisMutex)(nil)
