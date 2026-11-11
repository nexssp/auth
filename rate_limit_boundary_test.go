package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/nexssp/testkit"

	"github.com/nexssp/auth/security/ratelimit"
)

type requestLimitStub struct {
	allowed bool
	err     error
	keys    []string
}

func (limiter *requestLimitStub) Allow(_ context.Context, key string) (bool, error) {
	limiter.keys = append(limiter.keys, key)
	return limiter.allowed, limiter.err
}

var _ ratelimit.Limiter = (*requestLimitStub)(nil)

func TestRateLimitedRequestBoundaryNamespacesOperationsAndUsesOverrides(t *testing.T) {
	defaultLimiter := &requestLimitStub{allowed: true}
	registerLimiter := &requestLimitStub{allowed: false}
	next := &fakeBoundary{}
	boundary, err := NewRateLimitedRequestBoundary(next, RateLimitConfig{
		Default: defaultLimiter,
		Operations: map[BoundaryOperation]ratelimit.Limiter{
			BoundaryRegister: registerLimiter,
		},
		Key: func(context.Context, BoundaryOperation, *http.Request) (string, error) {
			return "trusted-client-digest", nil
		},
	})
	if err != nil {
		t.Fatalf("create rate-limited boundary: %v", err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/login", http.NoBody)
	if err := boundary.AuthorizeAuthRequest(request.Context(), BoundaryLogin, request, "challenge"); err != nil {
		t.Fatalf("authorize login: %v", err)
	}
	if got, want := defaultLimiter.keys, []string{"auth:login:trusted-client-digest"}; !equalStrings(got, want) {
		t.Fatalf("default limiter keys = %v, want %v", got, want)
	}
	if len(next.calls) != 1 || next.calls[0] != BoundaryLogin {
		t.Fatalf("host boundary calls = %v, want one login call", next.calls)
	}
	if err := boundary.AuthorizeAuthRequest(request.Context(), BoundaryRegister, request, "challenge"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("register error = %v, want ErrRateLimited", err)
	}
	if got, want := registerLimiter.keys, []string{"auth:register:trusted-client-digest"}; !equalStrings(got, want) {
		t.Fatalf("register limiter keys = %v, want %v", got, want)
	}
	if len(next.calls) != 1 {
		t.Fatalf("host boundary called after rate-limit denial: %v", next.calls)
	}
}

func TestRateLimitedRequestBoundaryFailsClosed(t *testing.T) {
	backendFailure := errors.New("limiter backend failed")
	limiter := &requestLimitStub{err: backendFailure}
	boundary, err := NewRateLimitedRequestBoundary(&fakeBoundary{}, RateLimitConfig{
		Default: limiter,
		Key: func(context.Context, BoundaryOperation, *http.Request) (string, error) {
			return "client", nil
		},
	})
	if err != nil {
		t.Fatalf("create rate-limited boundary: %v", err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/login", http.NoBody)
	if err := boundary.AuthorizeAuthRequest(request.Context(), BoundaryLogin, request, ""); !errors.Is(err, ErrRateLimiterUnavailable) || !errors.Is(err, backendFailure) {
		t.Fatalf("backend failure = %v, want wrapped ErrRateLimiterUnavailable and cause", err)
	}

	boundary, err = NewRateLimitedRequestBoundary(&fakeBoundary{}, RateLimitConfig{
		Default: &requestLimitStub{allowed: true},
		Key: func(context.Context, BoundaryOperation, *http.Request) (string, error) {
			return " ", nil
		},
	})
	if err != nil {
		t.Fatalf("create boundary with empty-key resolver: %v", err)
	}
	if err := boundary.AuthorizeAuthRequest(request.Context(), BoundaryLogin, request, ""); !errors.Is(err, ErrRequestDenied) {
		t.Fatalf("empty trusted key error = %v, want ErrRequestDenied", err)
	}
}

func TestRateLimitedRequestBoundaryRequiresCompleteConfiguration(t *testing.T) {
	key := func(context.Context, BoundaryOperation, *http.Request) (string, error) { return "client", nil }
	for _, config := range []RateLimitConfig{
		{Default: &requestLimitStub{allowed: true}},
		{Key: key},
		{Default: &requestLimitStub{allowed: true}, Key: key, Operations: map[BoundaryOperation]ratelimit.Limiter{"unknown": &requestLimitStub{allowed: true}}},
	} {
		if _, err := NewRateLimitedRequestBoundary(&fakeBoundary{}, config); err == nil {
			t.Fatalf("constructor accepted invalid configuration: %+v", config)
		}
	}
	if _, err := NewRateLimitedRequestBoundary(nil, RateLimitConfig{Default: &requestLimitStub{allowed: true}, Key: key}); err == nil {
		t.Fatal("constructor accepted a nil host boundary")
	}
}

func TestHTTPHandlerMapsRateLimitResultsWithTestkit(t *testing.T) {
	for _, test := range []struct {
		name    string
		limiter *requestLimitStub
		status  int
	}{
		{name: "denied", limiter: &requestLimitStub{allowed: false}, status: http.StatusTooManyRequests},
		{name: "backend unavailable", limiter: &requestLimitStub{err: errors.New("offline")}, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundary, err := NewRateLimitedRequestBoundary(&fakeBoundary{}, RateLimitConfig{
				Default: test.limiter,
				Key: func(context.Context, BoundaryOperation, *http.Request) (string, error) {
					return "trusted-client-digest", nil
				},
			})
			if err != nil {
				t.Fatalf("create rate-limited boundary: %v", err)
			}
			handler, err := NewHTTPHandler(HTTPConfig{Service: &Service{}, Boundary: boundary})
			if err != nil {
				t.Fatalf("create HTTP handler: %v", err)
			}
			suite := testkit.NewWithHandler(t, handler)
			suite.POST("/auth/login", map[string]string{"identifier": "person@example.test", "password": "not-used"}).Do().ExpectStatus(test.status)
		})
	}
}

func equalStrings(got, want []string) bool {
	return slices.Equal(got, want)
}
