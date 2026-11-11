package nexssflow

import (
	"context"

	"github.com/nexssp/auth"
)

// TurnstileActionBoundary composes host authorization with server-side
// Turnstile verification for selected Flow auth operations.
type TurnstileActionBoundary struct {
	next     ActionBoundary
	verifier auth.TurnstileVerifier
	required map[auth.BoundaryOperation]struct{}
}

// NewTurnstileActionBoundary constructs a Flow boundary that verifies tokens
// using the action name associated with each selected auth operation. The
// wrapped boundary should enforce trusted identity, origin/CSRF, registration
// rules, and rate limits, but should not separately verify the same token.
func NewTurnstileActionBoundary(next ActionBoundary, verifier auth.TurnstileVerifier, operations ...auth.BoundaryOperation) (*TurnstileActionBoundary, error) {
	if next == nil || verifier == nil {
		return nil, auth.ErrTurnstileConfiguration
	}
	if err := auth.ValidateTurnstileOperations(operations...); err != nil {
		return nil, err
	}
	required := make(map[auth.BoundaryOperation]struct{}, len(operations))
	for _, operation := range operations {
		required[operation] = struct{}{}
	}
	return &TurnstileActionBoundary{next: next, verifier: verifier, required: required}, nil
}

// AuthorizeAuthFlowAction runs the host's trusted-context checks before
// verifying a required Turnstile response.
func (boundary *TurnstileActionBoundary) AuthorizeAuthFlowAction(ctx context.Context, operation auth.BoundaryOperation, responseToken string) error {
	if boundary == nil || boundary.next == nil || boundary.verifier == nil {
		return auth.ErrTurnstileConfiguration
	}
	if err := boundary.next.AuthorizeAuthFlowAction(ctx, operation, responseToken); err != nil {
		return err
	}
	if _, required := boundary.required[operation]; !required {
		return nil
	}
	if responseToken == "" {
		return auth.ErrTurnstileRequired
	}
	action, ok := auth.TurnstileActionForOperation(operation)
	if !ok {
		return auth.ErrTurnstileConfiguration
	}
	return boundary.verifier.Verify(ctx, responseToken, action)
}
