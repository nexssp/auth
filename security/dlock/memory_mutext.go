// Path: nexss/auth/security/dlock/memory_mutex.go
package dlock

import (
	"context"
	"sync"
	"time"
)

type memoryLockEntry struct {
	expiresAt time.Time
}

// MemoryMutex provides an in-memory implementation of Mutex for single-node / testing.
type MemoryMutex struct {
	mu    sync.Mutex
	locks map[string]memoryLockEntry
}

func NewMemoryMutex() *MemoryMutex {
	return &MemoryMutex{
		locks: make(map[string]memoryLockEntry),
	}
}

func (m *MemoryMutex) TryLock(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if entry, ok := m.locks[key]; ok {
		if now.Before(entry.expiresAt) {
			return false, nil
		}
	}

	m.locks[key] = memoryLockEntry{expiresAt: now.Add(ttl)}
	return true, nil
}

func (m *MemoryMutex) Unlock(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.locks, key)
	return nil
}
