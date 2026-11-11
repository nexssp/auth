package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	cloudflareTurnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	maxTurnstileTokenBytes           = 2048
	maxTurnstileResponseBytes        = 8 << 10
	maxTurnstileRequestDuration      = 5 * time.Second
)

var (
	ErrTurnstileConfiguration = errors.New("turnstile is not configured correctly")
	ErrTurnstileRequired      = errors.New("a Turnstile response is required")
	ErrTurnstileRejected      = errors.New("turnstile response was rejected")
	ErrTurnstileUnavailable   = errors.New("turnstile verification is unavailable")
)

// TurnstileVerifier verifies a client response and binds it to the auth operation.
// Implementations must fail closed and must never log the secret or response token.
type TurnstileVerifier interface {
	Verify(ctx context.Context, responseToken, expectedAction string) error
}

// CloudflareTurnstileConfig contains server-only Siteverify settings. SecretKey
// must never be sent to a browser or stored in Flow source. ExpectedHostname is
// compared to Cloudflare's verified hostname response.
type CloudflareTurnstileConfig struct {
	SecretKey        string
	ExpectedHostname string
}

// CloudflareTurnstileVerifier verifies responses with Cloudflare Siteverify.
// Siteverify is called once per token; this client does not retry single-use tokens.
type CloudflareTurnstileVerifier struct {
	secretKey        string
	expectedHostname string
	client           *http.Client
}

type cloudflareSiteverifyResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// NewCloudflareTurnstileVerifier constructs a verifier with a fixed HTTPS
// endpoint, bounded response size, a five-second maximum timeout, and redirects
// disabled. No environment variables are read automatically.
func NewCloudflareTurnstileVerifier(config CloudflareTurnstileConfig) (*CloudflareTurnstileVerifier, error) {
	if config.SecretKey == "" || strings.TrimSpace(config.SecretKey) != config.SecretKey || len(config.SecretKey) > 512 || strings.ContainsAny(config.SecretKey, "\r\n\x00") {
		return nil, ErrTurnstileConfiguration
	}
	hostname, err := normalizeTurnstileHostname(config.ExpectedHostname)
	if err != nil {
		return nil, ErrTurnstileConfiguration
	}
	return &CloudflareTurnstileVerifier{
		secretKey:        config.SecretKey,
		expectedHostname: hostname,
		client: &http.Client{
			Timeout: maxTurnstileRequestDuration,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Verify sends the response token to Cloudflare and requires success, the
// configured hostname, and an exact action match. The optional remoteip field is
// deliberately omitted because this package cannot know whether proxy IP headers
// were validated by the host.
func (verifier *CloudflareTurnstileVerifier) Verify(ctx context.Context, responseToken, expectedAction string) error {
	if err := verifier.validateInput(ctx, responseToken, expectedAction); err != nil {
		return err
	}
	result, err := verifier.siteverify(ctx, responseToken)
	if err != nil {
		return err
	}
	return verifier.validateResponse(result, expectedAction)
}

func (verifier *CloudflareTurnstileVerifier) validateInput(ctx context.Context, responseToken, expectedAction string) error {
	if verifier == nil || verifier.client == nil || verifier.secretKey == "" || verifier.expectedHostname == "" {
		return ErrTurnstileConfiguration
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrTurnstileUnavailable
	}
	if responseToken == "" || len(responseToken) > maxTurnstileTokenBytes || strings.TrimSpace(responseToken) != responseToken || strings.ContainsAny(responseToken, "\r\n\x00") {
		return ErrTurnstileRejected
	}
	if !validTurnstileAction(expectedAction) {
		return ErrTurnstileConfiguration
	}
	return nil
}

func (verifier *CloudflareTurnstileVerifier) siteverify(ctx context.Context, responseToken string) (cloudflareSiteverifyResponse, error) {
	// #nosec G117 -- Siteverify requires this server-only secret in its HTTPS request body; it is never logged.
	requestBody, err := json.Marshal(struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
	}{Secret: verifier.secretKey, Response: responseToken})
	if err != nil {
		return cloudflareSiteverifyResponse{}, ErrTurnstileUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cloudflareTurnstileSiteverifyURL, bytes.NewReader(requestBody))
	if err != nil {
		return cloudflareSiteverifyResponse{}, ErrTurnstileUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := verifier.client.Do(request)
	if err != nil {
		return cloudflareSiteverifyResponse{}, ErrTurnstileUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTurnstileResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maxTurnstileResponseBytes || response.StatusCode != http.StatusOK {
		return cloudflareSiteverifyResponse{}, ErrTurnstileUnavailable
	}
	var result cloudflareSiteverifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return cloudflareSiteverifyResponse{}, ErrTurnstileUnavailable
	}
	return result, nil
}

func (verifier *CloudflareTurnstileVerifier) validateResponse(result cloudflareSiteverifyResponse, expectedAction string) error {
	if !result.Success {
		if turnstileServiceError(result.ErrorCodes) {
			return ErrTurnstileUnavailable
		}
		return ErrTurnstileRejected
	}
	hostname, err := normalizeTurnstileHostname(result.Hostname)
	if err != nil || hostname != verifier.expectedHostname || result.Action != expectedAction {
		return ErrTurnstileRejected
	}
	return nil
}

// NewTurnstileRequestBoundary wraps an existing host policy boundary and adds
// server-side verification for the selected operations. The wrapped boundary
// should enforce trusted identity, origin/CSRF, registration rules and rate
// limits, but should not separately verify the same Turnstile token.
func NewTurnstileRequestBoundary(next RequestBoundary, verifier TurnstileVerifier, operations ...BoundaryOperation) (*TurnstileRequestBoundary, error) {
	if next == nil || verifier == nil {
		return nil, ErrTurnstileConfiguration
	}
	if err := ValidateTurnstileOperations(operations...); err != nil {
		return nil, err
	}
	required := make(map[BoundaryOperation]struct{}, len(operations))
	for _, operation := range operations {
		required[operation] = struct{}{}
	}
	return &TurnstileRequestBoundary{next: next, verifier: verifier, required: required}, nil
}

// TurnstileRequestBoundary composes Turnstile verification with host request
// authorization. It must be constructed with NewTurnstileRequestBoundary.
type TurnstileRequestBoundary struct {
	next     RequestBoundary
	verifier TurnstileVerifier
	required map[BoundaryOperation]struct{}
}

// AuthorizeAuthRequest applies the host's checks first, then verifies a required
// Turnstile response before the auth service can consume credentials.
func (boundary *TurnstileRequestBoundary) AuthorizeAuthRequest(ctx context.Context, operation BoundaryOperation, request *http.Request, responseToken string) error {
	if boundary == nil || boundary.next == nil || boundary.verifier == nil {
		return ErrTurnstileConfiguration
	}
	if err := boundary.next.AuthorizeAuthRequest(ctx, operation, request, responseToken); err != nil {
		return err
	}
	if _, required := boundary.required[operation]; !required {
		return nil
	}
	if responseToken == "" {
		return ErrTurnstileRequired
	}
	action, ok := TurnstileActionForOperation(operation)
	if !ok {
		return ErrTurnstileConfiguration
	}
	return boundary.verifier.Verify(ctx, responseToken, action)
}

// DefaultTurnstileOperations returns operations that should receive a challenge
// by default in public browser-facing deployments. OAuth callbacks, authenticated
// account linking, logout, and PKCE code exchange use separate state/session
// protections and are intentionally not included.
func DefaultTurnstileOperations() []BoundaryOperation {
	return []BoundaryOperation{
		BoundaryLogin,
		BoundaryRegister,
		BoundaryPasswordReset,
		BoundaryEmailVerify,
		BoundaryOAuthBegin,
		BoundaryDesktopStart,
	}
}

// TurnstileActionForOperation returns the exact action string expected in the
// Siteverify response for operations that accept a client-supplied response token.
func TurnstileActionForOperation(operation BoundaryOperation) (string, bool) {
	switch operation {
	case BoundaryLogin, BoundaryRegister, BoundaryPasswordReset, BoundaryEmailVerify, BoundaryOAuthBegin, BoundaryDesktopStart:
		return string(operation), true
	case BoundaryOAuthCallback, BoundaryOAuthLink, BoundaryDesktopExchange, BoundaryLogout:
		return "", false
	}
	return "", false
}

// ValidateTurnstileOperations rejects operations that have no client-supplied
// Turnstile token in their request contract.
func ValidateTurnstileOperations(operations ...BoundaryOperation) error {
	if len(operations) == 0 {
		return ErrTurnstileConfiguration
	}
	for _, operation := range operations {
		if _, ok := TurnstileActionForOperation(operation); !ok {
			return ErrTurnstileConfiguration
		}
	}
	return nil
}

func normalizeTurnstileHostname(hostname string) (string, error) {
	if hostname == "" || strings.TrimSpace(hostname) != hostname {
		return "", ErrTurnstileConfiguration
	}
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	if hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "/\\:@?# \t\r\n\x00") {
		return "", ErrTurnstileConfiguration
	}
	for label := range strings.SplitSeq(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrTurnstileConfiguration
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", ErrTurnstileConfiguration
			}
		}
	}
	return hostname, nil
}

func validTurnstileAction(action string) bool {
	if len(action) < 2 || len(action) > 32 {
		return false
	}
	for _, char := range action {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func turnstileServiceError(codes []string) bool {
	for _, code := range codes {
		switch code {
		case "bad-request", "internal-error", "missing-input-secret", "invalid-input-secret":
			return true
		}
	}
	return false
}

// NewSecureHTTPHandler composes the default Turnstile gate with the host boundary
// before mounting public auth routes. Use NewHTTPHandler directly only when the
// host intentionally provides equivalent anti-abuse verification itself.
func NewSecureHTTPHandler(config HTTPConfig, verifier TurnstileVerifier) (*HTTPHandler, error) {
	boundary, err := NewTurnstileRequestBoundary(config.Boundary, verifier, DefaultTurnstileOperations()...)
	if err != nil {
		return nil, err
	}
	config.Boundary = boundary
	return NewHTTPHandler(config)
}
