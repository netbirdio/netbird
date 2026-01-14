package middleware

import "net/http"

// Chain creates a middleware chain
func Chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply middlewares in reverse order so they execute in the order provided
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
