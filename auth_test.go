package auth_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/testkit"
	"github.com/nexssp/transport/thttp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/nexssp/auth"
)

func setupAuthSuite(t *testing.T) (*testkit.Suite, *gorm.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	dbLogger := logger.Default.LogMode(logger.Silent)
	db, _ := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: dbLogger})
	store, _ := auth.NewGORMStore(db)

	cfg := auth.Config{
		Store:               store,
		Emailer:             auth.NoopEmailer{},
		Env:                 "test",
		BaseURL:             "http://localhost",
		AccessTTL:           15 * time.Minute,
		RefreshTTL:          24 * time.Hour,
		LoginRateLimitRPS:   1000,
		LoginRateLimitBurst: 1000,
		DesktopMode:         true,
	}

	plugin, _ := auth.New(cfg)

	protectedAction := action.New("admin.dashboard", func(_ context.Context, _ struct{}) (string, error) {
		return "welcome_admin", nil
	}).RequireRole("admin").Route(thttp.GET("/api/admin")).Build()

	tr := thttp.New(":0").Use(plugin.Protect())
	tr.Mount(plugin.Actions())
	tr.Mount([]action.AnyAction{protectedAction})

	return testkit.NewWithHandler(t, tr.Handler()), db
}

func TestLegacyPluginRequiresExplicitDevelopmentOrTestEnvironment(t *testing.T) {
	for _, environment := range []string{"", "staging", "production"} {
		t.Run(environment, func(t *testing.T) {
			if _, err := auth.New(auth.Config{Env: environment}); err == nil {
				t.Fatalf("auth.New accepted environment %q", environment)
			}
		})
	}
}

func TestAuth_RegisterAndLogin(t *testing.T) {
	t.Parallel()
	suite, db := setupAuthSuite(t)
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	suite.POST("/auth/register", map[string]string{
		"email":    "test@nexss.dev",
		"password": "SuperSecretPassword123!",
	}).Do().ExpectCreated()

	// Correct login -> 201 Created
	res := suite.POST("/auth/login", map[string]string{
		"email":    "test@nexss.dev",
		"password": "SuperSecretPassword123!",
	}).Do().ExpectOK()

	var body struct {
		Token struct {
			Access string `json:"access_token"`
		} `json:"token"`
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	res.Into(&body)

	if body.Token.Access == "" {
		t.Fatal("Login did not return an access token")
	}

	// Wrong password -> 401
	suite.POST("/auth/login", map[string]string{
		"email":    "test@nexss.dev",
		"password": "WrongPassword",
	}).Do().ExpectUnauthorized()
}

func TestAuth_RBACAndProtection(t *testing.T) {
	t.Parallel()
	suite, db := setupAuthSuite(t)
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	suite.POST("/auth/register", map[string]string{"email": "standard@nexss.dev", "password": "Password123!"}).Do().ExpectCreated()

	res := suite.POST("/auth/login", map[string]string{"email": "standard@nexss.dev", "password": "Password123!"}).Do().ExpectOK()
	var standardToken struct {
		Token struct {
			Access string `json:"access_token"`
		} `json:"token"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	res.Into(&standardToken)

	if standardToken.User.ID == "" {
		t.Fatal("user id is empty after login")
	}

	// Admin route without token fails
	suite.GET("/api/admin").Do().ExpectForbidden()

	// Admin route with standard user token fails
	suite.WithGlobalBearerToken(standardToken.Token.Access).GET("/api/admin").Do().ExpectForbidden()

	// Promote user to admin directly in DB
	if err := db.Create(&auth.RoleModel{UserID: standardToken.User.ID, Role: "admin"}).Error; err != nil {
		t.Fatalf("failed to promote user to admin: %v", err)
	}

	// Re-login to get updated claims
	res2 := suite.POST("/auth/login", map[string]string{"email": "standard@nexss.dev", "password": "Password123!"}).Do().ExpectOK()
	var adminToken struct {
		Token struct {
			Access string `json:"access_token"`
		} `json:"token"`
	}
	res2.Into(&adminToken)

	if adminToken.Token.Access == "" {
		t.Fatal("admin token access is empty")
	}

	// Admin route succeeds!
	suite.WithGlobalBearerToken(adminToken.Token.Access).GET("/api/admin").Do().ExpectOK().ContainsString("welcome_admin")
}

func TestAuth_TenantMustBeMemberAtLoginAndRefresh(t *testing.T) {
	t.Parallel()
	suite, db := setupAuthSuite(t)
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	const email = "tenant-user@nexss.dev"
	const password = "Password123!"
	suite.POST("/auth/register", map[string]string{"email": email, "password": password}).Do().ExpectCreated()

	initial := suite.POST("/auth/login", map[string]string{"email": email, "password": password}).Do().ExpectOK()
	var initialBody struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	initial.Into(&initialBody)
	if initialBody.User.ID == "" {
		t.Fatal("login returned an empty user ID")
	}

	if err := db.Create(&auth.TenantMemberModel{UserID: initialBody.User.ID, TenantID: "tenant-alpha", Role: "tenant-admin"}).Error; err != nil {
		t.Fatalf("create tenant membership: %v", err)
	}

	// The client cannot choose an arbitrary tenant while logging in.
	suite.POST("/auth/login", map[string]string{
		"email": email, "password": password, "tenant_id": "tenant-beta",
	}).Do().ExpectForbidden()

	// A permitted tenant is included in the issued session.
	login := suite.POST("/auth/login", map[string]string{
		"email": email, "password": password, "tenant_id": "tenant-alpha",
	}).Do().ExpectOK()
	var loginBody struct {
		Token struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
		} `json:"token"`
	}
	login.Into(&loginBody)
	parsed, err := auth.VerifyToken(loginBody.Token.Access)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("token claims type = %T, want jwt.MapClaims", parsed.Claims)
	}
	if got, _ := claims["ten"].(string); got != "tenant-alpha" {
		t.Fatalf("access token tenant = %q, want tenant-alpha", got)
	}

	// Revoking membership blocks future refreshes for the token's tenant.
	if err := db.Where("user_id = ? AND tenant_id = ?", initialBody.User.ID, "tenant-alpha").Delete(&auth.TenantMemberModel{}).Error; err != nil {
		t.Fatalf("remove tenant membership: %v", err)
	}
	suite.POST("/auth/refresh", map[string]string{"refresh_token": loginBody.Token.Refresh}).Do().ExpectForbidden()
}

func TestAuth_RefreshTokenUsesConfiguredTTL(t *testing.T) {
	t.Parallel()
	suite, db := setupAuthSuite(t)
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	suite.POST("/auth/register", map[string]string{"email": "refresh-ttl@nexss.dev", "password": "Password123!"}).Do().ExpectCreated()
	res := suite.POST("/auth/login", map[string]string{"email": "refresh-ttl@nexss.dev", "password": "Password123!"}).Do().ExpectOK()
	var body struct {
		Token struct {
			Refresh string `json:"refresh_token"`
		} `json:"token"`
	}
	res.Into(&body)

	parsed, err := auth.VerifyToken(body.Token.Refresh)
	if err != nil {
		t.Fatalf("verify refresh token: %v", err)
	}
	exp, ok := parsed.Claims.(jwt.MapClaims)["exp"].(float64)
	if !ok {
		t.Fatal("refresh token is missing a numeric exp claim")
	}
	remaining := time.Until(time.Unix(int64(exp), 0))
	if remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Fatalf("refresh token remaining TTL = %s, want approximately 24h", remaining)
	}
}

func TestGORMStore_ActionTokensAreHashedAtRest(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "tokens.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	store, err := auth.NewGORMStore(db)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	ctx := context.Background()
	const rawReset = "reset-bearer-token-that-must-not-be-stored"
	if err := store.CreateResetToken(ctx, "user-1", rawReset, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create reset token: %v", err)
	}
	var stored auth.ActionTokenModel
	if err := db.Where("type = ?", "reset").First(&stored).Error; err != nil {
		t.Fatalf("read stored reset token: %v", err)
	}
	if stored.Token == rawReset {
		t.Fatal("reset bearer token was persisted in plaintext")
	}
	if userID, err := store.GetResetToken(ctx, rawReset); err != nil || userID != "user-1" {
		t.Fatalf("hashed reset token lookup = (%q, %v), want (user-1, nil)", userID, err)
	}
	if err := store.DeleteResetToken(ctx, rawReset); err != nil {
		t.Fatalf("delete reset token: %v", err)
	}
	if _, err := store.GetResetToken(ctx, rawReset); err == nil {
		t.Fatal("deleted reset token remained valid")
	}
}
