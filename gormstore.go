package auth

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// ---------------------------------------------------------------------
// GORM Schema Definitions
// ---------------------------------------------------------------------

type UserModel struct {
	ID        string    `gorm:"primaryKey;type:varchar(36)"`
	Email     string    `gorm:"uniqueIndex;type:varchar(255);not null"`
	Password  []byte    `gorm:"not null"`
	Verified  bool      `gorm:"default:false;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

func (UserModel) TableName() string { return "auth_users" }

type RoleModel struct {
	UserID string `gorm:"primaryKey;type:varchar(36)"`
	Role   string `gorm:"primaryKey;type:varchar(64)"`
}

func (RoleModel) TableName() string { return "auth_roles" }

type PermissionModel struct {
	Role       string `gorm:"primaryKey;type:varchar(64)"`
	Permission string `gorm:"primaryKey;type:varchar(64)"`
}

func (PermissionModel) TableName() string { return "auth_permissions" }

type FeatureModel struct {
	UserID  string `gorm:"primaryKey;type:varchar(36)"`
	Feature string `gorm:"primaryKey;type:varchar(64)"`
}

func (FeatureModel) TableName() string { return "auth_user_features" }

type TenantMemberModel struct {
	TenantID string `gorm:"primaryKey;type:varchar(36)"`
	UserID   string `gorm:"primaryKey;type:varchar(36)"`
	Role     string `gorm:"type:varchar(64)"`
}

func (TenantMemberModel) TableName() string { return "auth_tenant_members" }

type TenantFeatureModel struct {
	TenantID string `gorm:"primaryKey;type:varchar(36)"`
	Feature  string `gorm:"primaryKey;type:varchar(64)"`
}

func (TenantFeatureModel) TableName() string { return "auth_tenant_features" }

type RefreshTokenModel struct {
	TokenID   string    `gorm:"primaryKey;type:varchar(36)"`
	UserID    string    `gorm:"index;type:varchar(36)"`
	ExpiresAt time.Time `gorm:"index"`
}

func (RefreshTokenModel) TableName() string { return "auth_refresh_tokens" }

type ActionTokenModel struct {
	Token     string    `gorm:"primaryKey;type:varchar(64)"`
	Type      string    `gorm:"index;type:varchar(16)"` // "verify" or "reset"
	UserID    string    `gorm:"index;type:varchar(36);not null"`
	ExpiresAt time.Time `gorm:"index"`
}

func (ActionTokenModel) TableName() string { return "auth_action_tokens" }

// OAuthAccountModel stores links between OAuth providers and local users.
type OAuthAccountModel struct {
	Provider       string `gorm:"primaryKey;type:varchar(64)"`
	ProviderUserID string `gorm:"primaryKey;type:varchar(128)"`
	UserID         string `gorm:"type:varchar(36);index;not null"`
}

func (OAuthAccountModel) TableName() string { return "auth_oauth_accounts" }

// ---------------------------------------------------------------------
// GORMStore Implementation
// ---------------------------------------------------------------------

type GORMStore struct {
	db *gorm.DB
}

func NewGORMStore(db *gorm.DB) (*GORMStore, error) {
	if err := db.AutoMigrate(
		&UserModel{},
		&RoleModel{},
		&PermissionModel{},
		&FeatureModel{},
		&TenantMemberModel{},
		&TenantFeatureModel{},
		&RefreshTokenModel{},
		&ActionTokenModel{},
		&OAuthAccountModel{},
	); err != nil {
		return nil, err
	}
	return &GORMStore{db: db}, nil
}

func (s *GORMStore) PruneExpiredTokens(ctx context.Context) error {
	now := time.Now()
	if err := s.db.WithContext(ctx).Where("expires_at < ?", now).Delete(&RefreshTokenModel{}).Error; err != nil {
		return err
	}
	return s.db.WithContext(ctx).Where("expires_at < ?", now).Delete(&ActionTokenModel{}).Error
}

func (s *GORMStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var m UserModel
	// Use Silent logger to prevent GORM from logging "record not found" as a WARN.
	// In the context of Auth, an email not being found is an expected domain state.
	if err := s.db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).WithContext(ctx).Where("email = ?", email).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return mapToUser(&m), nil
}

func (s *GORMStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	var m UserModel
	if err := s.db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return mapToUser(&m), nil
}

func (s *GORMStore) CreateUser(ctx context.Context, u *User) error {
	m := mapFromUser(u)
	if err := s.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return errors.New("user already exists")
		}
		return err
	}
	return nil
}

func (s *GORMStore) UpdateUser(ctx context.Context, u *User) error {
	return s.db.WithContext(ctx).Model(&UserModel{}).Where("id = ?", u.ID).Updates(mapFromUser(u)).Error
}

func (s *GORMStore) DeleteUser(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&UserModel{}).Error
}

func (s *GORMStore) GetRolePermissions(ctx context.Context, role string) ([]string, error) {
	var perms []string
	err := s.db.WithContext(ctx).Model(&PermissionModel{}).Where("role = ?", role).Pluck("permission", &perms).Error
	return perms, err
}

func (s *GORMStore) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	var roles []string
	err := s.db.WithContext(ctx).Model(&RoleModel{}).Where("user_id = ?", userID).Pluck("role", &roles).Error
	return roles, err
}

func (s *GORMStore) GetUserFeatures(ctx context.Context, userID string) ([]string, error) {
	var features []string
	err := s.db.WithContext(ctx).Model(&FeatureModel{}).Where("user_id = ?", userID).Pluck("feature", &features).Error
	return features, err
}

func (s *GORMStore) GetUserTenants(ctx context.Context, userID string) ([]TenantAccess, error) {
	var members []TenantMemberModel
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&members).Error; err != nil {
		return nil, err
	}
	out := make([]TenantAccess, len(members))
	for i, m := range members {
		out[i] = TenantAccess{TenantID: m.TenantID, Role: m.Role}
	}
	return out, nil
}

func (s *GORMStore) GetTenantRole(ctx context.Context, userID, tenantID string) (string, error) {
	var m TenantMemberModel
	if err := s.db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).WithContext(ctx).Where("user_id = ? AND tenant_id = ?", userID, tenantID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return m.Role, nil
}

func (s *GORMStore) GetTenantFeatures(ctx context.Context, tenantID string) ([]string, error) {
	var features []string
	err := s.db.WithContext(ctx).Model(&TenantFeatureModel{}).Where("tenant_id = ?", tenantID).Pluck("feature", &features).Error
	return features, err
}

func (s *GORMStore) CreateRefreshToken(ctx context.Context, userID, tokenID string, expiry time.Time) error {
	return s.db.WithContext(ctx).Create(&RefreshTokenModel{TokenID: tokenID, UserID: userID, ExpiresAt: expiry}).Error
}

func (s *GORMStore) ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) {
	var m RefreshTokenModel
	if err := s.db.WithContext(ctx).Where("token_id = ? AND expires_at > ?", tokenID, time.Now()).First(&m).Error; err != nil {
		return "", errors.New("invalid token")
	}
	return m.UserID, nil
}

func (s *GORMStore) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	return s.db.WithContext(ctx).Where("token_id = ?", tokenID).Delete(&RefreshTokenModel{}).Error
}

func (s *GORMStore) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&RefreshTokenModel{}).Error
}

func (s *GORMStore) CreateVerificationToken(ctx context.Context, userID, token string, expiry time.Time) error {
	return s.db.WithContext(ctx).Create(&ActionTokenModel{Token: actionTokenKey(token), Type: "verify", UserID: userID, ExpiresAt: expiry}).Error
}

func (s *GORMStore) GetVerificationToken(ctx context.Context, token string) (string, error) {
	return s.getActionToken(ctx, token, "verify")
}

func (s *GORMStore) DeleteVerificationToken(ctx context.Context, token string) error {
	return s.db.WithContext(ctx).Where("token = ? AND type = ?", actionTokenKey(token), "verify").Delete(&ActionTokenModel{}).Error
}

func (s *GORMStore) CreateResetToken(ctx context.Context, userID, token string, expiry time.Time) error {
	return s.db.WithContext(ctx).Create(&ActionTokenModel{Token: actionTokenKey(token), Type: "reset", UserID: userID, ExpiresAt: expiry}).Error
}

func (s *GORMStore) GetResetToken(ctx context.Context, token string) (string, error) {
	return s.getActionToken(ctx, token, "reset")
}

func (s *GORMStore) DeleteResetToken(ctx context.Context, token string) error {
	return s.db.WithContext(ctx).Where("token = ? AND type = ?", actionTokenKey(token), "reset").Delete(&ActionTokenModel{}).Error
}

func (s *GORMStore) GetOAuthAccount(ctx context.Context, provider, providerUserID string) (string, error) {
	var acc OAuthAccountModel
	err := s.db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&acc).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return acc.UserID, nil
}

func (s *GORMStore) LinkOAuthAccount(ctx context.Context, userID, provider, providerUserID string) error {
	acc := OAuthAccountModel{
		Provider:       provider,
		ProviderUserID: providerUserID,
		UserID:         userID,
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&acc).Error
}

func (s *GORMStore) getActionToken(ctx context.Context, token, typ string) (string, error) {
	var m ActionTokenModel
	if err := s.db.WithContext(ctx).Where("token = ? AND type = ? AND expires_at > ?", actionTokenKey(token), typ, time.Now()).First(&m).Error; err != nil {
		return "", errors.New("invalid or expired token")
	}
	return m.UserID, nil
}

func mapToUser(m *UserModel) *User {
	return &User{ID: m.ID, Email: m.Email, Password: m.Password, Verified: m.Verified, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

func mapFromUser(u *User) *UserModel {
	return &UserModel{ID: u.ID, Email: u.Email, Password: u.Password, Verified: u.Verified, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}
