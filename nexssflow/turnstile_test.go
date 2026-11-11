package nexssflow

import (
	"context"
	"errors"
	"testing"

	"github.com/nexssp/auth"
)

type flowTurnstileVerifierFunc func(context.Context, string, string) error

func (verify flowTurnstileVerifierFunc) Verify(ctx context.Context, responseToken, expectedAction string) error {
	return verify(ctx, responseToken, expectedAction)
}

func TestTurnstileActionBoundaryVerifiesActionBoundResponse(t *testing.T) {
	base := &flowTestBoundary{}
	var gotToken, gotAction string
	verifier := flowTurnstileVerifierFunc(func(_ context.Context, token, action string) error {
		gotToken, gotAction = token, action
		return nil
	})
	boundary, err := NewTurnstileActionBoundary(base, verifier, auth.BoundaryLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.AuthorizeAuthFlowAction(context.Background(), auth.BoundaryLogin, "test-response"); err != nil {
		t.Fatalf("AuthorizeAuthFlowAction returned error: %v", err)
	}
	if gotToken != "test-response" || gotAction != "login" {
		t.Fatalf("verified token/action = %q/%q", gotToken, gotAction)
	}
	if calls := base.calls(); len(calls) != 1 || calls[0] != (flowBoundaryCall{operation: auth.BoundaryLogin, token: "test-response"}) {
		t.Fatalf("host boundary calls = %#v", calls)
	}
}

func TestTurnstileActionBoundaryRequiresTokenAndPreservesHostDenial(t *testing.T) {
	base := &flowTestBoundary{}
	verificationCalls := 0
	verifier := flowTurnstileVerifierFunc(func(context.Context, string, string) error {
		verificationCalls++
		return nil
	})
	boundary, err := NewTurnstileActionBoundary(base, verifier, auth.BoundaryLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.AuthorizeAuthFlowAction(context.Background(), auth.BoundaryLogin, ""); !errors.Is(err, auth.ErrTurnstileRequired) {
		t.Fatalf("missing-token error = %v, want ErrTurnstileRequired", err)
	}
	if verificationCalls != 0 {
		t.Fatalf("verifier calls = %d, want 0 for missing token", verificationCalls)
	}

	base.reject = auth.ErrRateLimited
	if err := boundary.AuthorizeAuthFlowAction(context.Background(), auth.BoundaryLogin, "test-response"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("host denial = %v, want ErrRateLimited", err)
	}
	if verificationCalls != 0 {
		t.Fatalf("verifier calls = %d, want 0 after host denial", verificationCalls)
	}
}

func TestTurnstileActionBoundaryRejectsUnsupportedOperation(t *testing.T) {
	_, err := NewTurnstileActionBoundary(&flowTestBoundary{}, flowTurnstileVerifierFunc(func(context.Context, string, string) error { return nil }), auth.BoundaryOAuthCallback)
	if !errors.Is(err, auth.ErrTurnstileConfiguration) {
		t.Fatalf("constructor error = %v, want ErrTurnstileConfiguration", err)
	}
}
