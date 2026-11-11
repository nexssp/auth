package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/transport/thttp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/nexssp/auth/security/fail2ban"
	"github.com/nexssp/auth/security/ratelimit"
)

type Plugin struct {
	cfg     Config
	actions []action.AnyAction
	protect func(http.Handler) http.Handler

	oauthStates    map[string]*oauthProviderState
	bruteProtector fail2ban.Protector
}

func New(cfg Config) (*Plugin, error) {
	cfg.applyDefaults()

	isDev := cfg.DesktopMode || strings.EqualFold(cfg.Env, "development")

	if cfg.JWTPrivateKey == nil || cfg.JWTPublicKey == nil {
		if isDev {
			if err := InitTempKeys(); err != nil {
				return nil, fmt.Errorf("auth: temp keys: %w", err)
			}
			slog.Warn("Auth: using ephemeral JWT keys (development mode)")
		} else {
			return nil, errors.New("auth: JWT keys required in production")
		}
	} else {
		if err := InitKeys(cfg.JWTPrivateKey, cfg.JWTPublicKey); err != nil {
			return nil, fmt.Errorf("auth: invalid keys: %w", err)
		}
	}

	p := &Plugin{cfg: cfg}

	p.bruteProtector = p.createBruteProtector()

	p.actions = []action.AnyAction{
		p.buildRegister(),
		p.buildLogin(),
		p.buildLogin2FA(),
		p.buildLogout(),
		p.buildRefresh(),
		p.buildForgotPassword(),
		p.buildResetPassword(),
		p.buildConfirmEmail(),
		p.buildResendVerification(),
		p.buildMe(),
		p.buildOAuthLogin(),
		p.buildOAuthCallback(),
		p.buildOAuthProviders(),
	}

	p.protect = JWTMiddleware(JWTConfig{
		VerifyFn: func(ctx context.Context, t string) (jwt.MapClaims, error) {
			tok, err := VerifyToken(t)
			if err != nil || !tok.Valid {
				return nil, err
			}
			return tok.Claims.(jwt.MapClaims), nil
		},
		Optional:    cfg.DesktopMode,
		PublicPaths: cfg.PublicPaths,

		TokenSource: func(r *http.Request) string {
			if v := r.Header.Get("Authorization"); len(v) > 7 && v[:7] == "Bearer " {
				return v[7:]
			}
			return r.URL.Query().Get("token")
		},
	})

	return p, nil
}

func (p *Plugin) Actions() []action.AnyAction              { return p.actions }
func (p *Plugin) Protect() func(http.Handler) http.Handler { return p.protect }

func (p *Plugin) createBruteProtector() fail2ban.Protector {
	redisURL := os.Getenv("AUTH_REDIS_URL")
	if redisURL == "" {
		redisURL = os.Getenv("REDIS_URL")
	}

	if redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err == nil {
			rdb := redis.NewClient(opts)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rdb.Ping(ctx).Err(); err == nil {
				return fail2ban.NewRedisProtector(rdb, "auth:f2b", p.cfg.LoginMaxFailures, p.cfg.LoginFailWindow, p.cfg.LoginLockout)
			}
		}
	}
	return fail2ban.NewMemoryProtector(p.cfg.LoginMaxFailures, p.cfg.LoginFailWindow, p.cfg.LoginLockout)
}

type credentialsReq struct {
	Email              string `json:"email" validate:"required,email"`
	Password           string `json:"password" validate:"required,min=8,max=72"`
	TenantID           string `json:"tenant_id,omitempty"`
	TrustedDeviceToken string `json:"trusted_device_token,omitempty"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *refreshReq) FromHTTPRequest(req *http.Request) error {
	if req.Body != nil && req.ContentLength > 0 {
		_ = json.NewDecoder(req.Body).Decode(r)
	}
	if r.RefreshToken == "" {
		if c, err := req.Cookie("refresh_token"); err == nil {
			r.RefreshToken = c.Value
		}
	}
	return nil
}

type tokenReq struct {
	Token string `json:"token" validate:"required"`
}

type forgotPasswordReq struct {
	Email string `json:"email" validate:"required,email"`
}

type resetReq struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type authRes struct {
	Token              Token  `json:"token"`
	User               User   `json:"user"`
	Requires2FA        bool   `json:"requires_2fa,omitempty"`
	SessionToken       string `json:"session_token,omitempty"`
	TrustedDeviceToken string `json:"trusted_device_token,omitempty"`

	MFAHint string `json:"mfa_hint,omitempty"`
	MFAType string `json:"mfa_type,omitempty"`
}

type login2FAReq struct {
	SessionToken string `json:"session_token" validate:"required"`
	Code         string `json:"code" validate:"required,len=6"`
	TrustDevice  bool   `json:"trust_device"`
}

func (p *Plugin) createRateLimiter() action.RateLimiter {
	redisURL := os.Getenv("AUTH_REDIS_URL")
	if redisURL == "" {
		redisURL = os.Getenv("REDIS_URL")
	}
	namespace := os.Getenv("APP_NAME")
	if namespace == "" {
		namespace = "auth-service"
	}

	if redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err == nil {
			rdb := redis.NewClient(opts)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rdb.Ping(ctx).Err(); err == nil {
				return ratelimit.NewRedisLimiter(rdb, p.cfg.LoginRateLimitRPS, p.cfg.LoginRateLimitBurst, namespace)
			}
		}
	}
	return ratelimit.NewMemoryLimiter(p.cfg.LoginRateLimitRPS, p.cfg.LoginRateLimitBurst)
}

func (p *Plugin) buildMe() action.AnyAction {
	return action.New("auth.me", func(ctx context.Context, _ struct{}) (User, error) {
		userID := xctx.UserIDFrom(ctx)
		if userID == "" {
			return User{}, xerr.Unauthorized("unauthenticated")
		}

		user, err := p.cfg.Store.GetUserByID(context.WithoutCancel(ctx), userID)
		if err != nil || user == nil {
			return User{}, xerr.Unauthorized("user not found")
		}

		return *user, nil
	}).
		SuccessStatus(http.StatusOK).
		Description("Returns the currently authenticated user profile").
		Tag("auth").
		Route(thttp.GET("/auth/me")).Build()
}

func (p *Plugin) buildRegister() action.AnyAction {
	lim := p.createRateLimiter()

	return action.New("auth.register", func(ctx context.Context, req credentialsReq) (*action.MessageRes, error) {
		existing, err := p.cfg.Store.GetUserByEmail(ctx, req.Email)
		if err != nil {
			return nil, xerr.Database("database lookup failed", err)
		}
		if existing != nil {
			return nil, xerr.Conflict("email already registered")
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, xerr.Internal("failed to hash password", err)
		}

		user := &User{
			ID:        generateID(),
			Email:     req.Email,
			Password:  hashed,
			Verified:  p.cfg.DesktopMode,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		safeCtx := context.WithoutCancel(ctx)

		if err := p.cfg.Store.CreateUser(safeCtx, user); err != nil {
			return nil, xerr.Database("failed to create user", err)
		}

		slog.InfoContext(safeCtx, "user_registered", "user_id", user.ID, "email", user.Email)
		if !p.cfg.DesktopMode {
			go p.sendVerification(safeCtx, user)
		}

		return &action.MessageRes{Message: "verification email sent"}, nil
	}).
		Description("Registers a new user and sends verification email").Tag("auth").
		SuccessStatus(http.StatusCreated).
		RateLimitDistributed(lim, xctx.ClientIPFrom).
		ConcurrencyLimit(p.cfg.LoginConcurrency).Timeout(p.cfg.LoginTimeout).
		Route(thttp.POST("/auth/register")).Build()
}

func (p *Plugin) buildResendVerification() action.AnyAction {
	type resendReq struct {
		Email string `json:"email" validate:"required,email"`
	}
	lim := p.createRateLimiter()
	return action.New("auth.resend-verification", func(ctx context.Context, req resendReq) (*action.MessageRes, error) {
		user, err := p.cfg.Store.GetUserByEmail(ctx, req.Email)
		if err != nil || user == nil || user.Verified {
			return &action.MessageRes{Message: "If the email exists and is not verified, a new link was sent"}, nil
		}
		go p.sendVerification(context.WithoutCancel(ctx), user)
		return &action.MessageRes{Message: "If the email exists and is not verified, a new link was sent"}, nil
	}).
		RateLimitDistributed(lim, xctx.ClientIPFrom).
		ConcurrencyLimit(p.cfg.LoginConcurrency).Timeout(p.cfg.LoginTimeout).
		Route(thttp.POST("/auth/resend-verification")).Build()
}

func (p *Plugin) buildLogin() action.AnyAction {
	lim := p.createRateLimiter()

	return action.New("auth.login", func(ctx context.Context, req credentialsReq) (authRes, error) {
		user, err := p.cfg.Store.GetUserByEmail(ctx, req.Email)
		if err != nil {
			return authRes{}, xerr.Database("lookup failed", err)
		}

		var hash []byte
		if user != nil {
			hash = user.Password
		} else {
			hash = []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOh231v4fFkC6.2qg07aE3wS8jXkXW.K2")
		}

		err = bcrypt.CompareHashAndPassword(hash, []byte(req.Password))
		valid := 0
		if err == nil && user != nil {
			valid = 1
		}
		if subtle.ConstantTimeByteEq(byte(valid), 0) == 1 {
			return authRes{}, xerr.Unauthorized("Nieprawidłowy adres e-mail lub hasło")
		}
		if !user.Verified {
			return authRes{}, xerr.Unauthorized("Konto nie jest zweryfikowane")
		}

		safeCtx := context.WithoutCancel(ctx)

		requires2FA := false
		mfaEnabled := true
		if envMfa := os.Getenv("AUTH_MFA_REQUIRED"); envMfa != "" {
			mfaEnabled = envMfa == "true"
		} else if p.cfg.Env == "development" || p.cfg.Env == "dev" || p.cfg.DesktopMode {
			mfaEnabled = false
		}

		if mfaEnabled && len(p.cfg.MFAProviders) > 0 {
			requires2FA = true

			if req.TrustedDeviceToken != "" {
				if tok, err := VerifyToken(req.TrustedDeviceToken); err == nil {
					if claims, ok := tok.Claims.(jwt.MapClaims); ok && claims["type"] == "trusted_device" && claims["sub"] == user.ID {
						requires2FA = false
					}
				}
			}
		}

		if len(p.cfg.MFAProviders) == 0 {
			requires2FA = false
		}

		if requires2FA {
			max := big.NewInt(1000000)
			n, _ := rand.Int(rand.Reader, max)
			code := fmt.Sprintf("%06d", n.Int64())

			dbToken := user.ID + ":" + code
			exp := time.Now().Add(5 * time.Minute)
			if err := p.cfg.Store.CreateVerificationToken(safeCtx, user.ID, dbToken, exp); err != nil {
				return authRes{}, xerr.Database("Błąd generowania sesji", err)
			}

			if tmplMailer, ok := p.cfg.Emailer.(interface {
				SendTemplate(context.Context, string, string, string, any) error
			}); ok {
				go tmplMailer.SendTemplate(safeCtx, user.Email, "Twój kod logowania", "auth", map[string]string{
					"Title":      "Logowanie 2FA",
					"Message":    "Twój jednorazowy kod logowania to: " + code,
					"Link":       "#",
					"ButtonText": code,
					"TTL":        "5 minut",
				})
			} else {
				go p.cfg.Emailer.Send(safeCtx, user.Email, "Kod logowania", "Twój kod to: "+code)
			}

			tempTokens, _ := GenerateTokensWithClaims(jwt.MapClaims{
				"sub":  user.ID,
				"type": "pre-auth",
				"exp":  time.Now().Add(5 * time.Minute).Unix(),
			})

			return authRes{
				Requires2FA:  true,
				SessionToken: tempTokens.Access,
			}, nil
		}

		return p.issueTokens(safeCtx, user, req.TenantID)
	}).
		SuccessStatus(http.StatusOK).
		Tag("auth").
		RateLimitDistributed(lim, xctx.ClientIPFrom).
		Use(fail2ban.Fail2Ban[credentialsReq, authRes](p.bruteProtector, func(ctx context.Context, _ credentialsReq) string { return xctx.ClientIPFrom(ctx) })).
		ConcurrencyLimit(p.cfg.LoginConcurrency).Timeout(p.cfg.LoginTimeout).
		Route(thttp.POST("/auth/login")).Build()
}

func (p *Plugin) buildLogin2FA() action.AnyAction {
	lim := p.createRateLimiter()

	return action.New("auth.login_2fa", func(ctx context.Context, req login2FAReq) (authRes, error) {
		tok, err := VerifyToken(req.SessionToken)
		if err != nil {
			return authRes{}, xerr.Unauthorized("Sesja wygasła. Zaloguj się ponownie.")
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok || claims["type"] != "pre-auth" {
			return authRes{}, xerr.Unauthorized("Nieprawidłowy token sesji.")
		}

		userID, ok := claims["sub"].(string)
		if !ok || userID == "" {
			return authRes{}, xerr.Unauthorized("Brak identyfikatora w tokenie.")
		}

		safeCtx := context.WithoutCancel(ctx)

		dbToken := userID + ":" + req.Code
		tokenUserID, err := p.cfg.Store.GetVerificationToken(safeCtx, dbToken)
		if err != nil || tokenUserID != userID {
			return authRes{}, xerr.Unauthorized("Nieprawidłowy lub wygasły kod.")
		}

		_ = p.cfg.Store.DeleteVerificationToken(safeCtx, dbToken)

		user, err := p.cfg.Store.GetUserByID(safeCtx, userID)
		if err != nil || user == nil {
			return authRes{}, xerr.Internal("Nie znaleziono użytkownika.", err)
		}

		res, err := p.issueTokens(safeCtx, user, "")
		if err != nil {
			return authRes{}, xerr.Internal("Błąd generowania tokenów dostępu.", err)
		}

		if req.TrustDevice {
			trustedClaims := jwt.MapClaims{
				"sub":  user.ID,
				"type": "trusted_device",
				"exp":  time.Now().Add(30 * 24 * time.Hour).Unix(),
			}
			trustedTokens, err := GenerateTokensWithClaims(trustedClaims)
			if err == nil {
				res.TrustedDeviceToken = trustedTokens.Access
			}
		}

		return res, nil
	}).
		SuccessStatus(http.StatusOK).
		Description("Weryfikuje krok 2FA i loguje użytkownika.").
		Tag("auth").
		RateLimitDistributed(lim, xctx.ClientIPFrom).
		Route(thttp.POST("/auth/login/2fa")).Build()
}

func (p *Plugin) buildRefresh() action.AnyAction {
	return action.New("auth.refresh", func(ctx context.Context, req refreshReq) (Token, error) {
		if req.RefreshToken == "" {
			return Token{}, xerr.BadRequest("missing refresh token")
		}

		tok, err := VerifyToken(req.RefreshToken)
		if err != nil {
			return Token{}, xerr.Unauthorized("invalid token signature")
		}

		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			return Token{}, xerr.Unauthorized("invalid claims")
		}

		tokenID, _ := claims["jti"].(string)
		if tokenID == "" {
			return Token{}, xerr.Unauthorized("missing token id")
		}

		safeCtx := context.WithoutCancel(ctx)

		userID, err := p.cfg.Store.ValidateRefreshToken(safeCtx, tokenID)
		if err != nil {
			return Token{}, xerr.Unauthorized("refresh token expired or revoked")
		}

		_ = p.cfg.Store.RevokeRefreshToken(safeCtx, tokenID)

		user, err := p.cfg.Store.GetUserByID(safeCtx, userID)
		if err != nil || user == nil {
			return Token{}, xerr.Unauthorized("user no longer exists")
		}

		tenantID, _ := claims["ten"].(string)
		res, err := p.issueTokens(safeCtx, user, tenantID)
		return res.Token, err
	}).SuccessStatus(http.StatusOK).Description("Rotates JWT tokens").Tag("auth").Route(thttp.POST("/auth/refresh")).Build()
}

func (p *Plugin) buildLogout() action.AnyAction {
	return action.New("auth.logout", func(ctx context.Context, req refreshReq) (*action.MessageRes, error) {
		if req.RefreshToken != "" {
			if tok, err := VerifyToken(req.RefreshToken); err == nil {
				if claims, ok := tok.Claims.(jwt.MapClaims); ok {
					if jti, _ := claims["jti"].(string); jti != "" {
						_ = p.cfg.Store.RevokeRefreshToken(context.WithoutCancel(ctx), jti)
					}
				}
			}
		}
		return &action.MessageRes{Message: "logged out"}, nil
	}).SuccessStatus(http.StatusOK).Description("Revokes refresh token").Tag("auth").Route(thttp.POST("/auth/logout")).Build()
}

func (p *Plugin) buildForgotPassword() action.AnyAction {
	lim := p.createRateLimiter()
	return action.New("auth.forgot-password", func(ctx context.Context, req forgotPasswordReq) (*action.MessageRes, error) {
		safeCtx := context.WithoutCancel(ctx)

		user, _ := p.cfg.Store.GetUserByEmail(safeCtx, req.Email)
		if user == nil {
			return &action.MessageRes{Message: "If the email exists, a reset link was sent"}, nil
		}

		token := generateURLToken()
		if err := p.cfg.Store.CreateResetToken(safeCtx, user.ID, token, time.Now().Add(p.cfg.ResetTokenTTL)); err != nil {
			return nil, xerr.Database("failed to create password reset token", err)
		}

		if p.cfg.Emailer != nil {
			url := fmt.Sprintf("%s/reset-password?token=%s", p.cfg.BaseURL, token)
			if m, ok := p.cfg.Emailer.(interface {
				SendTemplate(context.Context, string, string, string, any) error
			}); ok {
				go m.SendTemplate(safeCtx, user.Email, "Zresetuj swoje hasło w systemie", "auth", map[string]string{
					"Title":      "Resetowanie hasła",
					"Message":    "Otrzymaliśmy prośbę o zresetowanie hasła dla Twojego konta. Kliknij w poniższy przycisk, aby ustawić nowe.",
					"Link":       url,
					"ButtonText": "Zresetuj hasło",
					"TTL":        "1 godzinę",
				})
			} else {
				go p.cfg.Emailer.Send(safeCtx, user.Email, "Zresetuj hasło", "Kliknij tutaj: "+url)
			}
		}
		return &action.MessageRes{Message: "If the email exists, a reset link was sent"}, nil
	}).
		SuccessStatus(http.StatusOK).
		RateLimitDistributed(lim, xctx.ClientIPFrom).
		ConcurrencyLimit(p.cfg.LoginConcurrency).Timeout(p.cfg.LoginTimeout).
		Route(thttp.POST("/auth/forgot-password")).Build()
}

func (p *Plugin) buildResetPassword() action.AnyAction {
	return action.New("auth.reset-password", func(ctx context.Context, req resetReq) (*action.MessageRes, error) {
		safeCtx := context.WithoutCancel(ctx)

		userID, err := p.cfg.Store.GetResetToken(safeCtx, req.Token)
		if err != nil {
			return nil, xerr.BadRequest("invalid or expired token")
		}

		user, _ := p.cfg.Store.GetUserByID(safeCtx, userID)
		if user == nil {
			return nil, xerr.NotFound("user not found")
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, xerr.Internal("failed to hash password", err)
		}
		user.Password = hash
		user.UpdatedAt = time.Now()
		if err := p.cfg.Store.UpdateUser(safeCtx, user); err != nil {
			return nil, xerr.Database("failed to update password", err)
		}

		if err := p.cfg.Store.DeleteResetToken(safeCtx, req.Token); err != nil {
			return nil, xerr.Database("failed to consume password reset token", err)
		}
		if err := p.cfg.Store.RevokeAllUserTokens(safeCtx, userID); err != nil {
			return nil, xerr.Database("failed to revoke active tokens", err)
		}

		return &action.MessageRes{Message: "password updated"}, nil
	}).SuccessStatus(http.StatusOK).Route(thttp.POST("/auth/reset-password")).Build()
}

func (p *Plugin) buildConfirmEmail() action.AnyAction {
	return action.New("auth.confirm-email", func(ctx context.Context, req tokenReq) (authRes, error) {
		safeCtx := context.WithoutCancel(ctx)

		if req.Token == "" {
			return authRes{}, xerr.BadRequest("token is required")
		}

		userID, err := p.cfg.Store.GetVerificationToken(safeCtx, req.Token)
		if err != nil {
			return authRes{}, xerr.BadRequest("invalid or expired token")
		}

		user, err := p.cfg.Store.GetUserByID(safeCtx, userID)
		if err != nil || user == nil {
			return authRes{}, xerr.NotFound("user not found")
		}

		if !user.Verified {
			user.Verified = true
			user.UpdatedAt = time.Now()
			if err := p.cfg.Store.UpdateUser(safeCtx, user); err != nil {
				return authRes{}, xerr.Internal("failed to update user", err)
			}
			slog.InfoContext(safeCtx, "user_verified", "user_id", user.ID)
		}

		_ = p.cfg.Store.DeleteVerificationToken(safeCtx, req.Token)
		_ = p.cfg.Store.RevokeAllUserTokens(safeCtx, user.ID)

		res, err := p.issueTokens(safeCtx, user, "")
		if err != nil {
			return authRes{}, xerr.Internal("failed to issue tokens", err)
		}

		slog.InfoContext(safeCtx, "email_confirmed_and_logged_in", "user_id", user.ID)
		return res, nil
	}).SuccessStatus(http.StatusOK).Route(thttp.POST("/auth/confirm-email")).Build()
}

func (p *Plugin) issueTokens(ctx context.Context, user *User, requestedTenantID string) (authRes, error) {
	roles, _ := p.cfg.Store.GetUserRoles(ctx, user.ID)
	features, _ := p.cfg.Store.GetUserFeatures(ctx, user.ID)

	tenantID, tenantRole, err := p.resolveTenant(ctx, user.ID, requestedTenantID)
	if err != nil {
		return authRes{}, err
	}
	if tenantRole != "" {
		roles = append(roles, tenantRole)
	}
	if tenantID != "" {
		if tf, err := p.cfg.Store.GetTenantFeatures(ctx, tenantID); err == nil {
			features = append(features, tf...)
		}
	}

	var perms []string
	for _, r := range roles {
		if rp, err := p.cfg.Store.GetRolePermissions(ctx, r); err == nil {
			perms = append(perms, rp...)
		}
	}

	tokenID := uuid.NewString()
	expAccess := time.Now().Add(p.cfg.AccessTTL)
	expRefresh := time.Now().Add(p.cfg.RefreshTTL)

	if err := p.cfg.Store.CreateRefreshToken(ctx, user.ID, tokenID, expRefresh); err != nil {
		return authRes{}, xerr.Database("failed to store refresh token", err)
	}

	claims := jwt.MapClaims{
		"sub":                user.ID,
		"email":              user.Email,
		"preferred_username": strings.Split(user.Email, "@")[0],
		"ten":                tenantID,
		"roles":              roles,
		"perms":              perms,
		"features":           features,
		"jti":                tokenID,
		"exp":                expAccess.Unix(),
		"iat":                time.Now().Unix(),
		"verified":           user.Verified,
	}

	tokens, err := generateTokensWithClaims(claims, p.cfg.RefreshTTL)
	if err != nil {
		return authRes{}, xerr.Internal("token generation failed", err)
	}

	return authRes{
		Token: Token{Access: tokens.Access, Refresh: tokens.Refresh},
		User:  *user,
	}, nil
}

// resolveTenant selects a tenant only from memberships persisted by the Store. A
// requested tenant is never trusted merely because it was supplied by a client.
func (p *Plugin) resolveTenant(ctx context.Context, userID, requestedTenantID string) (tenantID, tenantRole string, err error) {
	tenants, err := p.cfg.Store.GetUserTenants(ctx, userID)
	if err != nil {
		return "", "", xerr.Database("failed to load tenant memberships", err)
	}

	if requestedTenantID != "" {
		for _, tenant := range tenants {
			if tenant.TenantID == requestedTenantID {
				return tenant.TenantID, tenant.Role, nil
			}
		}
		return "", "", xerr.Forbidden("tenant access denied")
	}

	if len(tenants) > 0 {
		return tenants[0].TenantID, tenants[0].Role, nil
	}

	// Users without an explicit membership retain the framework's personal-tenant
	// behaviour. Client-supplied tenant IDs still require a stored membership.
	return userID, "", nil
}

func (p *Plugin) sendVerification(ctx context.Context, user *User) {
	token := generateURLToken()
	expiry := time.Now().Add(p.cfg.VerifyTokenTTL)
	if err := p.cfg.Store.CreateVerificationToken(ctx, user.ID, token, expiry); err != nil {
		slog.ErrorContext(ctx, "failed to create verification token", "user_id", user.ID, "error", err)
		return
	}

	url := fmt.Sprintf("%s/confirm-email?token=%s", p.cfg.BaseURL, token)

	if tmplMailer, ok := p.cfg.Emailer.(interface {
		SendTemplate(context.Context, string, string, string, any) error
	}); ok {
		_ = tmplMailer.SendTemplate(ctx, user.Email, "Verify your email", "auth", map[string]string{
			"Title":      "Welcome to the system!",
			"Message":    "Please confirm your email address by clicking the button below.",
			"Link":       url,
			"ButtonText": "Confirm email",
			"TTL":        "24 hours",
		})
	} else {
		_ = p.cfg.Emailer.Send(ctx, user.Email, "Verify your email", "Click here to verify: "+url)
	}
	slog.InfoContext(ctx, "verification_email_sent", "user_id", user.ID, "email", user.Email)
}

func generateID() string {
	return uuid.NewString()
}

func generateURLToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
