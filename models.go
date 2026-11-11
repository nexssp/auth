// Legacy identity, tenancy, token, and provider models retained for compatibility.
package auth

import (
	"context"
	"time"
)

// ---------------------------------------------------------------------
// Domain Models
// ---------------------------------------------------------------------

// User represents the core identity in the system.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  []byte    `json:"-"` // Never leak the hashed password
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Token holds standard OAuth2/OIDC token pairs.
type Token struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

// OAuthConfig defines an external identity provider (Google, Microsoft, etc.)
type OAuthConfig struct {
	Provider     string // e.g., "google"
	ClientID     string
	ClientSecret string
	RedirectURL  string   // e.g., "http://localhost:33669/auth/oauth/google/callback"
	IssuerURL    string   // e.g., "https://accounts.google.com"
	Scopes       []string // e.g., []string{"openid", "profile", "email"}
}

// ---------------------------------------------------------------------
// Store Contract
// ---------------------------------------------------------------------

// Store defines the persistence surface for the legacy Plugin. It combines
// identity, token, provider, role, feature, and tenancy operations; it is not the
// storage contract used by Service and does not provide its atomicity guarantees.
//
// Deprecated: Implement the storage interfaces needed by Service for new hosts.
//
//nolint:interfacebloat // Store is a legacy compatibility contract spanning the plugin subsystems.
type Store interface {
	// User CRUD
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error

	// RBAC & Features
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
	GetRolePermissions(ctx context.Context, role string) ([]string, error)
	GetUserFeatures(ctx context.Context, userID string) ([]string, error)

	// Multi-Tenancy
	GetUserTenants(ctx context.Context, userID string) ([]TenantAccess, error)
	GetTenantRole(ctx context.Context, userID, tenantID string) (string, error)
	GetTenantFeatures(ctx context.Context, tenantID string) ([]string, error)

	// Token Management (Refresh & Revocation)
	CreateRefreshToken(ctx context.Context, userID, tokenID string, expiry time.Time) error
	ValidateRefreshToken(ctx context.Context, tokenID string) (userID string, err error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	PruneExpiredTokens(ctx context.Context) error

	// Email Verification & Password Reset
	CreateVerificationToken(ctx context.Context, userID, token string, expiry time.Time) error
	GetVerificationToken(ctx context.Context, token string) (userID string, err error)
	DeleteVerificationToken(ctx context.Context, token string) error

	CreateResetToken(ctx context.Context, userID, token string, expiry time.Time) error
	GetResetToken(ctx context.Context, token string) (userID string, err error)
	DeleteResetToken(ctx context.Context, token string) error

	// OAuth 2.0
	GetOAuthAccount(ctx context.Context, provider, providerUserID string) (userID string, err error)
	LinkOAuthAccount(ctx context.Context, userID, provider, providerUserID string) error
}

// ---------------------------------------------------------------------
// Emailer & Configuration
// ---------------------------------------------------------------------

// Emailer abstracts outbound transactional emails.
type Emailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Config controls the legacy authentication plugin.
//
// Deprecated: Config is for development/test compatibility. Production hosts
// must supply adapters through Service and use the guarded HTTP or Flow APIs.
type Config struct {
	Store         Store
	Emailer       Emailer
	JWTPublicKey  []byte
	JWTPrivateKey []byte
	BaseURL       string // e.g., "https://app.example.com"
	Env           string // "development", "production", etc.

	// Token Lifecycles
	AccessTTL      time.Duration // Default: 15m
	RefreshTTL     time.Duration // Default: 30d
	ResetTokenTTL  time.Duration // Default: 1h
	VerifyTokenTTL time.Duration // Default: 24h

	// Brute-force & DDoS Protection (Login Endpoint)
	LoginRateLimitRPS   float64       // Default: 5.0
	LoginRateLimitBurst int           // Default: 2
	LoginConcurrency    int32         // Default: 20 (Prevents bcrypt CPU starvation)
	LoginTimeout        time.Duration // Default: 3s

	// Semantic Brute-Force Protection (Fail2Ban)
	LoginMaxFailures int           // e.g., 5 failed attempts
	LoginFailWindow  time.Duration // e.g., within 15 minutes
	LoginLockout     time.Duration // e.g., ban for 30 minutes

	// DesktopMode enables legacy local-development behavior. It does not make the
	// legacy plugin suitable for production or public network exposure.
	DesktopMode bool

	// PublicPaths bypasses JWT validation for specified prefixes.
	PublicPaths []string

	OAuthProviders []OAuthConfig

	MFAProviders map[string]MFAProvider

	ActionCodeTTL time.Duration
}

func (c *Config) applyDefaults() {
	if c.AccessTTL == 0 {
		c.AccessTTL = 15 * time.Minute
	}
	if c.RefreshTTL == 0 {
		c.RefreshTTL = 30 * 24 * time.Hour
	}
	if c.ResetTokenTTL == 0 {
		c.ResetTokenTTL = 1 * time.Hour
	}
	if c.VerifyTokenTTL == 0 {
		c.VerifyTokenTTL = 24 * time.Hour
	}
	if c.LoginRateLimitRPS == 0 {
		c.LoginRateLimitRPS = 5.0
	}
	if c.LoginRateLimitBurst == 0 {
		c.LoginRateLimitBurst = 2
	}
	if c.LoginConcurrency == 0 {
		c.LoginConcurrency = 20
	}
	if c.LoginTimeout == 0 {
		c.LoginTimeout = 3 * time.Second
	}

	if c.LoginMaxFailures == 0 {
		c.LoginMaxFailures = 5
	}
	if c.LoginFailWindow == 0 {
		c.LoginFailWindow = 15 * time.Minute
	}
	if c.LoginLockout == 0 {
		c.LoginLockout = 30 * time.Minute
	}

	if len(c.PublicPaths) == 0 {
		c.PublicPaths = []string{
			"/auth/login",
			"/auth/register",
			"/auth/refresh",
			"/auth/forgot-password",
			"/auth/reset-password",
			"/auth/confirm-email",
			"/auth/resend-verification",
			"/auth/oauth/",
			"/health",
			"/public/",
		}
	}
}

// MFAProvider definiuje kontrakt dla strategii autoryzacji dwuetapowej (Strategy Pattern).
// Umożliwia łatwe dodawanie SMS, TOTP, WebAuthn itp. bez zmiany rdzenia.
type MFAProvider interface {
	ID() string
	Name() string
	Type() string // Zwraca typ interfejsu UI: "code", "webauthn", "push"

	Challenge(ctx context.Context, user *User) (hint string, err error)
	Verify(ctx context.Context, user *User, input string) error
}
