package nexssflow

import (
	"context"
	"errors"

	"github.com/nexssp/auth"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
)

type runtimeDependenciesKey struct{}

type runtimeDependencies struct {
	service  *auth.Service
	boundary ActionBoundary
}

// WithRuntimeDependencies adds the host-owned auth service and Flow action
// boundary to the context for one Flow execution. For HTTP routes, call it from
// the host middleware so each request receives its own trusted dependencies.
func WithRuntimeDependencies(ctx context.Context, service *auth.Service, boundary ActionBoundary) (context.Context, error) {
	if ctx == nil {
		return nil, errors.New("nexssflow: runtime context is required")
	}
	if service == nil || boundary == nil {
		return nil, errors.New("nexssflow: auth service and Flow action boundary are required")
	}
	return context.WithValue(ctx, runtimeDependenciesKey{}, runtimeDependencies{
		service: service, boundary: boundary,
	}), nil
}

func runtimeDependenciesFromContext(ctx context.Context) (runtimeDependencies, error) {
	if ctx != nil {
		if dependencies, ok := ctx.Value(runtimeDependenciesKey{}).(runtimeDependencies); ok && dependencies.service != nil && dependencies.boundary != nil {
			return dependencies, nil
		}
	}
	return runtimeDependencies{}, xerr.Unavailable("Authentication runtime dependencies are unavailable")
}

func runtimeAction[Request, Response any](name, description string, factory func(*auth.Service, ActionBoundary) action.AnyAction) *action.BuiltAction[Request, Response] {
	return action.New(name, func(ctx context.Context, request Request) (Response, error) {
		var zero Response
		dependencies, err := runtimeDependenciesFromContext(ctx)
		if err != nil {
			return zero, err
		}
		result, err := factory(dependencies.service, dependencies.boundary).DoAny(ctx, request)
		if err != nil {
			return zero, err
		}
		response, ok := result.(Response)
		if !ok {
			return zero, xerr.Internal("Authentication action failed")
		}
		return response, nil
	}).Description(description).Internal().Build()
}
