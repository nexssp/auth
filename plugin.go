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

// New constructs the legacy JWT/plugin API.
//
// Deprecated: This API is restricted to explicitly named development/test
// environments. Production hosts should use NewService and the guarded HTTP or
// Flow APIs with host-owned persistence, session, and request-boundary adapters.
func New(cfg Config) (*Plugin, error) {
	if !isLegacyDevelopmentEnvironment(cfg.Env) {
		return nil, errors.New("auth: legacy Plugin is available only in development/test environments; use NewService for production")
	}
	cfg.applyDefaults()

	isDev := isLegacyDevelopmentEnvironment(cfg.Env)

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
		VerifyFn: func(_ context.Context, t string) (jwt.MapClaims, error) {
			tok, err := VerifyToken(t)
			if err != nil || !tok.Valid {
				return nil, err
			}
			claims, ok := tok.Claims.(jwt.MapClaims)
			if !ok {
				return nil, errors.New("auth: invalid token claims")
			}
			return claims, nil
		},
		Optional:    cfg.DesktopMode,
		PublicPaths: cfg.PublicPaths,

		TokenSource: bearerToken,
	})

	return p, nil
}

func isLegacyDevelopmentEnvironment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "dev", "development", "test":
		return true
	default:
		return false
	}
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
		if err := json.NewDecoder(req.Body).Decode(r); err != nil {
			return xerr.BadRequest("invalid request body")
		}
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
		if err != nil && !errors.Is(err, ErrAccountNotFound) {
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
			return &action.MessageRes{Message: "If the email exists and is not verified, a new link was sent"}, nil //nolint:nilerr // Keep lookup failures indistinguishable from unknown accounts.
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
		if err != nil && !errors.Is(err, ErrAccountNotFound) {
			return authRes{}, xerr.Database("lookup failed", err)
		}
		if errors.Is(err, ErrAccountNotFound) {
			user = nil
		}
		if !validLegacyLoginPassword(user, req.Password) {
			return authRes{}, xerr.Unauthorized("Nieprawidłowy adres e-mail lub hasło") //nolint:misspell // "adres" is correct Polish for "address".
		}
		if !user.Verified {
			return authRes{}, xerr.Unauthorized("Konto nie jest zweryfikowane")
		}

		safeCtx := context.WithoutCancel(ctx)
		if p.requiresSecondFactor(req.TrustedDeviceToken, user.ID) {
			return p.sendMFAChallenge(safeCtx, user)
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

func validLegacyLoginPassword(user *User, password string) bool {
	hash := []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOh231v4fFkC6.2qg07aE3wS8jXkXW.K2")
	if user != nil {
		hash = user.Password
	}
	compareErr := bcrypt.CompareHashAndPassword(hash, []byte(password))
	valid := 0
	if compareErr == nil && user != nil {
		valid = 1
	}
	return subtle.ConstantTimeByteEq(byte(valid), 0) != 1
}

func (p *Plugin) requiresSecondFactor(trustedDeviceToken, userID string) bool {
	if len(p.cfg.MFAProviders) == 0 {
		return false
	}
	enabled := true
	if configured := os.Getenv("AUTH_MFA_REQUIRED"); configured != "" {
		enabled = configured == "true"
	} else if p.cfg.Env == "development" || p.cfg.Env == "dev" || p.cfg.DesktopMode {
		enabled = false
	}
	if !enabled {
		return false
	}
	if trustedDeviceToken == "" {
		return true
	}
	token, err := VerifyToken(trustedDeviceToken)
	if err != nil || token == nil {
		return true
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return !ok || claims["type"] != "trusted_device" || claims["sub"] != userID
}

func (p *Plugin) sendMFAChallenge(ctx context.Context, user *User) (authRes, error) {
	upperBound := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return authRes{}, xerr.Internal("Błąd generowania kodu 2FA", err)
	}
	code := fmt.Sprintf("%06d", n.Int64())
	dbToken := user.ID + ":" + code
	expiresAt := time.Now().Add(5 * time.Minute)
	if storeErr := p.cfg.Store.CreateVerificationToken(ctx, user.ID, dbToken, expiresAt); storeErr != nil {
		return authRes{}, xerr.Database("Błąd generowania sesji", storeErr)
	}

	if tmplMailer, ok := p.cfg.Emailer.(interface {
		SendTemplate(context.Context, string, string, string, any) error
	}); ok {
		go func() {
			if deliveryErr := tmplMailer.SendTemplate(ctx, user.Email, "Twój kod logowania", "auth", map[string]string{
				templateTitle:   "Logowanie 2FA",
				templateMessage: "Twój jednorazowy kod logowania to: " + code,
				"Link":          "#",
				templateButton:  code,
				"TTL":           "5 minut",
			}); deliveryErr != nil {
				slog.ErrorContext(ctx, "MFA email delivery failed")
			}
		}()
	} else {
		go func() {
			if deliveryErr := p.cfg.Emailer.Send(ctx, user.Email, "Kod logowania", "Twój kod to: "+code); deliveryErr != nil {
				slog.ErrorContext(ctx, "MFA email delivery failed")
			}
		}()
	}

	tokens, err := GenerateTokensWithClaims(jwt.MapClaims{
		"sub":  user.ID,
		"type": "pre-auth",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		return authRes{}, xerr.Internal("Błąd generowania sesji 2FA", err)
	}
	return authRes{Requires2FA: true, SessionToken: tokens.Access}, nil
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

		if cleanupErr := p.cfg.Store.DeleteVerificationToken(safeCtx, dbToken); cleanupErr != nil {
			slog.ErrorContext(safeCtx, "MFA verification token cleanup failed")
		}

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

		if revokeErr := p.cfg.Store.RevokeRefreshToken(safeCtx, tokenID); revokeErr != nil {
			return Token{}, xerr.Database("failed to revoke refresh token", revokeErr)
		}

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
						if revokeErr := p.cfg.Store.RevokeRefreshToken(context.WithoutCancel(ctx), jti); revokeErr != nil {
							slog.ErrorContext(ctx, "refresh token revocation failed")
						}
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

		user, err := p.cfg.Store.GetUserByEmail(safeCtx, req.Email)
		if err != nil {
			slog.ErrorContext(safeCtx, "password reset account lookup failed")
			return &action.MessageRes{Message: "If the email exists, a reset link was sent"}, nil //nolint:nilerr // Avoid exposing account lookup failures through the reset response.
		}
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
				go func() {
					if err := m.SendTemplate(safeCtx, user.Email, "Zresetuj swoje hasło w systemie", "auth", map[string]string{
						templateTitle:   "Resetowanie hasła",
						templateMessage: "Otrzymaliśmy prośbę o zresetowanie hasła dla Twojego konta. Kliknij w poniższy przycisk, aby ustawić now.",
						"Link":          url,
						templateButton:  "Zresetuj hasło",
						"TTL":           "1 godzinę",
					}); err != nil {
						slog.ErrorContext(safeCtx, "password reset email delivery failed")
					}
				}()
			} else {
				go func() {
					if err := p.cfg.Emailer.Send(safeCtx, user.Email, "Zresetuj hasło", "Kliknij tutaj: "+url); err != nil {
						slog.ErrorContext(safeCtx, "password reset email delivery failed")
					}
				}()
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

		user, err := p.cfg.Store.GetUserByID(safeCtx, userID)
		if err != nil {
			return nil, xerr.Database("failed to load user", err)
		}
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
			if updateErr := p.cfg.Store.UpdateUser(safeCtx, user); updateErr != nil {
				return authRes{}, xerr.Internal("failed to update user", updateErr)
			}
			slog.InfoContext(safeCtx, "user_verified", "user_id", user.ID)
		}

		if cleanupErr := p.cfg.Store.DeleteVerificationToken(safeCtx, req.Token); cleanupErr != nil {
			slog.ErrorContext(safeCtx, "email verification token cleanup failed")
		}
		if revokeErr := p.cfg.Store.RevokeAllUserTokens(safeCtx, user.ID); revokeErr != nil {
			slog.ErrorContext(safeCtx, "user token revocation failed")
		}

		res, err := p.issueTokens(safeCtx, user, "")
		if err != nil {
			return authRes{}, xerr.Internal("failed to issue tokens", err)
		}

		slog.InfoContext(safeCtx, "email_confirmed_and_logged_in", "user_id", user.ID)
		return res, nil
	}).SuccessStatus(http.StatusOK).Route(thttp.POST("/auth/confirm-email")).Build()
}

func (p *Plugin) issueTokens(ctx context.Context, user *User, requestedTenantID string) (authRes, error) {
	roles, err := p.cfg.Store.GetUserRoles(ctx, user.ID)
	if err != nil {
		return authRes{}, xerr.Database("failed to load user roles", err)
	}
	features, err := p.cfg.Store.GetUserFeatures(ctx, user.ID)
	if err != nil {
		return authRes{}, xerr.Database("failed to load user features", err)
	}

	tenantID, tenantRole, err := p.resolveTenant(ctx, user.ID, requestedTenantID)
	if err != nil {
		return authRes{}, err
	}
	if tenantRole != "" {
		roles = append(roles, tenantRole)
	}
	if tenantID != "" {
		tenantFeatures, tenantErr := p.cfg.Store.GetTenantFeatures(ctx, tenantID)
		if tenantErr != nil {
			return authRes{}, xerr.Database("failed to load tenant features", tenantErr)
		}
		features = append(features, tenantFeatures...)
	}

	var perms []string
	for _, r := range roles {
		rolePermissions, permissionErr := p.cfg.Store.GetRolePermissions(ctx, r)
		if permissionErr != nil {
			return authRes{}, xerr.Database("failed to load role permissions", permissionErr)
		}
		perms = append(perms, rolePermissions...)
	}

	tokenID := uuid.NewString()
	expAccess := time.Now().Add(p.cfg.AccessTTL)
	expRefresh := time.Now().Add(p.cfg.RefreshTTL)

	if createErr := p.cfg.Store.CreateRefreshToken(ctx, user.ID, tokenID, expRefresh); createErr != nil {
		return authRes{}, xerr.Database("failed to store refresh token", createErr)
	}

	claims := jwt.MapClaims{
		"sub":                user.ID,
		emailField:           user.Email,
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
	// behavior. Client-supplied tenant IDs still require a stored membership.
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
		if err := tmplMailer.SendTemplate(ctx, user.Email, "Verify your email", "auth", map[string]string{
			templateTitle:   "Welcome to the system!",
			templateMessage: "Please confirm your email address by clicking the button below.",
			"Link":          url,
			templateButton:  "Confirm email",
			"TTL":           "24 hours",
		}); err != nil {
			slog.ErrorContext(ctx, "verification email delivery failed")
		}
	} else {
		if err := p.cfg.Emailer.Send(ctx, user.Email, "Verify your email", "Click here to verify: "+url); err != nil {
			slog.ErrorContext(ctx, "verification email delivery failed")
		}
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
