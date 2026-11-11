package auth

import (
	"context"
	"net/http"
)

type httpExchangeContextKey struct{}

// HTTPExchange carries the live HTTP request and response writer for one
// request. It is intentionally request-scoped: host-owned BrowserSessionHost
// implementations can read the validated request and write/clear session
// cookies before the response is committed. Never log or serialize it.
type HTTPExchange struct {
	Request  *http.Request
	Response http.ResponseWriter
}

// WithHTTPExchange attaches the active HTTP exchange to ctx. A nil ctx is
// returned unchanged; callers should supply a request context.
func WithHTTPExchange(ctx context.Context, request *http.Request, response http.ResponseWriter) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, httpExchangeContextKey{}, HTTPExchange{
		Request: request, Response: response,
	})
}

// HTTPExchangeFromContext returns the request-scoped exchange, if one was
// attached by the HTTP host.
func HTTPExchangeFromContext(ctx context.Context) (HTTPExchange, bool) {
	if ctx == nil {
		return HTTPExchange{}, false
	}
	exchange, ok := ctx.Value(httpExchangeContextKey{}).(HTTPExchange)
	return exchange, ok && exchange.Request != nil && exchange.Response != nil
}
