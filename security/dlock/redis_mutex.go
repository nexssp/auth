package dlock

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisMutex implements action.Mutex using Redis SET with NX option.
type RedisMutex struct {
	client *redis.Client
	prefix string
}

func NewRedisMutex(client *redis.Client) *RedisMutex {
	return &RedisMutex{client: client, prefix: "nexss:dlock:"}
}

func (m *RedisMutex) TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	res, err := m.client.SetArgs(ctx, m.prefix+key, "locked", redis.SetArgs{
		Mode: "NX",
		TTL:  ttl,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return res == "OK", nil
}

func (m *RedisMutex) Unlock(ctx context.Context, key string) error {
	return m.client.Del(ctx, m.prefix+key).Err()
}
