// nexss/plugins/auth/memorystore.go
package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

type memoryStore struct {
	mu    sync.RWMutex
	users map[string]User   // email -> User
	ids   map[string]string // id -> email

	roles map[string][]string // userID -> roles
	perms map[string][]string // role -> permissions
	feats map[string][]string // userID -> features

	tenants map[string]map[string]string // tenantID -> userID -> Role

	tokens map[string]tokenEntry // tokenId -> entry

	// OAuth: provider -> providerUserID -> userID
	oauth map[string]map[string]string
}

type tokenEntry struct {
	userID string
	typ    string
	expiry time.Time
}

func NewMemoryStore() Store {
	return &memoryStore{
		users:   make(map[string]User),
		ids:     make(map[string]string),
		roles:   make(map[string][]string),
		perms:   make(map[string][]string),
		feats:   make(map[string][]string),
		tenants: make(map[string]map[string]string),
		tokens:  make(map[string]tokenEntry),
		oauth:   make(map[string]map[string]string),
	}
}

func (s *memoryStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.users[email]; ok {
		return &u, nil
	}
	return nil, ErrAccountNotFound
}

func (s *memoryStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if email, ok := s.ids[id]; ok {
		u := s.users[email]
		return &u, nil
	}
	return nil, ErrAccountNotFound
}

func (s *memoryStore) CreateUser(_ context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.Email]; exists {
		return errors.New("user already exists")
	}
	s.users[user.Email] = *user
	s.ids[user.ID] = user.Email
	return nil
}

func (s *memoryStore) UpdateUser(_ context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.Email]; !exists {
		return errors.New("not found")
	}
	s.users[user.Email] = *user
	return nil
}

func (s *memoryStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if email, ok := s.ids[id]; ok {
		delete(s.users, email)
		delete(s.ids, id)
	}
	return nil
}

func (s *memoryStore) GetUserRoles(_ context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.roles[userID]...), nil
}

func (s *memoryStore) GetRolePermissions(_ context.Context, role string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.perms[role]...), nil
}

func (s *memoryStore) GetUserFeatures(_ context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.feats[userID]...), nil
}

func (s *memoryStore) GetUserTenants(_ context.Context, userID string) ([]TenantAccess, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []TenantAccess
	for tid, members := range s.tenants {
		if role, ok := members[userID]; ok {
			out = append(out, TenantAccess{TenantID: tid, Role: role})
		}
	}
	return out, nil
}

func (s *memoryStore) GetTenantRole(_ context.Context, userID, tenantID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if members, ok := s.tenants[tenantID]; ok {
		return members[userID], nil
	}
	return "", nil
}

func (s *memoryStore) GetTenantFeatures(_ context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	if tenantFeats, ok := s.feats["tenant:"+tenantID]; ok {
		out = append(out, tenantFeats...)
	}
	return out, nil
}

func (s *memoryStore) CreateRefreshToken(_ context.Context, userID, tokenID string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenID] = tokenEntry{userID: userID, typ: "refresh", expiry: expiry}
	return nil
}

func (s *memoryStore) ValidateRefreshToken(_ context.Context, tokenID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.tokens[tokenID]; ok && entry.typ == "refresh" && time.Now().Before(entry.expiry) {
		return entry.userID, nil
	}
	return "", errors.New("invalid")
}

func (s *memoryStore) RevokeRefreshToken(_ context.Context, tokenID string) error {
	s.mu.Lock()
	delete(s.tokens, tokenID)
	s.mu.Unlock()
	return nil
}

func (s *memoryStore) RevokeAllUserTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.tokens {
		if v.userID == userID {
			delete(s.tokens, k)
		}
	}
	return nil
}

func (s *memoryStore) CreateVerificationToken(_ context.Context, u, t string, exp time.Time) error {
	return s.setToken(t, "verify", u, exp)
}

func (s *memoryStore) GetVerificationToken(_ context.Context, t string) (string, error) {
	return s.getToken(t, "verify")
}

func (s *memoryStore) DeleteVerificationToken(_ context.Context, t string) error {
	return s.delToken(t)
}

func (s *memoryStore) CreateResetToken(_ context.Context, u, t string, exp time.Time) error {
	return s.setToken(t, "reset", u, exp)
}

func (s *memoryStore) GetResetToken(_ context.Context, t string) (string, error) {
	return s.getToken(t, "reset")
}

func (s *memoryStore) DeleteResetToken(_ context.Context, t string) error {
	return s.delToken(t)
}

// ---------------------------------------------------------------------
// OAuth Methods
// ---------------------------------------------------------------------

func (s *memoryStore) GetOAuthAccount(_ context.Context, provider, providerUserID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if providerMap, ok := s.oauth[provider]; ok {
		if userID, ok := providerMap[providerUserID]; ok {
			return userID, nil
		}
	}
	return "", nil
}

func (s *memoryStore) LinkOAuthAccount(_ context.Context, userID, provider, providerUserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oauth[provider] == nil {
		s.oauth[provider] = make(map[string]string)
	}
	s.oauth[provider][providerUserID] = userID
	return nil
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

func (s *memoryStore) setToken(t, typ, uid string, exp time.Time) error {
	s.mu.Lock()
	s.tokens[actionTokenKey(t)] = tokenEntry{userID: uid, typ: typ, expiry: exp}
	s.mu.Unlock()
	return nil
}

func (s *memoryStore) getToken(t, typ string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.tokens[actionTokenKey(t)]; ok && entry.typ == typ && time.Now().Before(entry.expiry) {
		return entry.userID, nil
	}
	return "", errors.New("invalid")
}

func (s *memoryStore) delToken(t string) error {
	s.mu.Lock()
	delete(s.tokens, actionTokenKey(t))
	s.mu.Unlock()
	return nil
}

func (s *memoryStore) PruneExpiredTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.tokens {
		if now.After(v.expiry) {
			delete(s.tokens, k)
		}
	}
	return nil
}
