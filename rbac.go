package auth

import "context"

// RBACStore is the interface for providing RBAC data from the master DB.
// Implement this in your user service layer.
type RBACStore interface {
	GetUserFeatures(ctx context.Context, userID string) ([]string, error)
	GetUserTenants(ctx context.Context, userID string) ([]TenantAccess, error)
	HasTenantAccess(ctx context.Context, userID, tenantID string) (bool, string, error)
}

type TenantAccess struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"` // admin, operator, viewer
}

// FeatureSet provides O(1) feature flag lookups.
type FeatureSet map[string]struct{}

func NewFeatureSet(features []string) FeatureSet {
	fs := make(FeatureSet, len(features))
	for _, f := range features {
		fs[f] = struct{}{}
	}
	return fs
}

func (fs FeatureSet) Has(feature string) bool {
	_, ok := fs[feature]
	return ok
}
