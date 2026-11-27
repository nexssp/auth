// Path: nexss/auth/security/dlock/memory_mutex.go
package dlock

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type memoryLockEntry struct {
	owner     string
	expiresAt time.Time
}

// MemoryMutex provides an in-memory implementation of Mutex for single-node / testing.
type MemoryMutex struct {
	mu           sync.Mutex
	locks        map[string]memoryLockEntry
	legacyMu     sync.Mutex
	legacyLeases map[string]Lease
}

func NewMemoryMutex() *MemoryMutex {
	return &MemoryMutex{
		locks:        make(map[string]memoryLockEntry),
		legacyLeases: make(map[string]Lease),
	}
}

func (m *MemoryMutex) TryAcquire(ctx context.Context, key string, ttl time.Duration) (Lease, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if key == "" || ttl <= 0 {
		return nil, false, errors.New("dlock: key and positive TTL are required")
	}
	owner := uuid.NewString()
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if entry, ok := m.locks[key]; ok {
		if now.Before(entry.expiresAt) {
			return nil, false, nil
		}
	}

	m.locks[key] = memoryLockEntry{owner: owner, expiresAt: now.Add(ttl)}
	return &memoryLease{mutex: m, key: key, owner: owner}, true, nil
}

func (m *MemoryMutex) TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
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

func (m *MemoryMutex) Unlock(ctx context.Context, key string) error {
	m.legacyMu.Lock()
	lease := m.legacyLeases[key]
	delete(m.legacyLeases, key)
	m.legacyMu.Unlock()
	if lease == nil {
		return nil
	}
	return lease.Unlock(ctx)
}

type memoryLease struct {
	mutex *MemoryMutex
	key   string
	owner string
}

func (lease *memoryLease) Unlock(_ context.Context) error {
	lease.mutex.mu.Lock()
	defer lease.mutex.mu.Unlock()
	if entry, ok := lease.mutex.locks[lease.key]; ok && entry.owner == lease.owner {
		delete(lease.mutex.locks, lease.key)
	}
	return nil
}

var _ LeaseMutex = (*MemoryMutex)(nil)
