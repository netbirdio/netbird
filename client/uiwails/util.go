//go:build !(linux && 386)

package main

import (
	"context"
	"time"
)

// defaultContext returns a context with the given timeout.
func defaultContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
