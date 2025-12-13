//go:build !js

package grpc

import (
	"context"
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	webSocketFallbackEnabled     bool
	webSocketFallbackEnabledLock sync.RWMutex
)

// EnableWebSocketFallback enables WebSocket transport after auto-detection
func EnableWebSocketFallback() {
	webSocketFallbackEnabledLock.Lock()
	defer webSocketFallbackEnabledLock.Unlock()
	if !webSocketFallbackEnabled {
		webSocketFallbackEnabled = true
		log.Info("WebSocket fallback enabled - HTTP/2 connection issues detected (ALPN/proxy restrictions)")
	}
}

// IsWebSocketFallbackEnabled returns true if WebSocket fallback was auto-enabled
func IsWebSocketFallbackEnabled() bool {
	webSocketFallbackEnabledLock.RLock()
	defer webSocketFallbackEnabledLock.RUnlock()
	return webSocketFallbackEnabled
}

// ShouldFallbackToWebSocket checks if the error indicates we should try WebSocket.
// This detects connection-layer failures typically caused by ALPN stripping or HTTP/2 blocking proxies.
func ShouldFallbackToWebSocket(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded (wrapped or unwrapped)
	// This catches timeouts that occur when proxies silently drop HTTP/2 traffic
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Unwrap to find the gRPC status error
	var currentErr error = err
	for currentErr != nil {
		if s, ok := status.FromError(currentErr); ok {
			switch s.Code() {
			// Unavailable: connection refused, DNS failures, or transport-layer issues
			// including ALPN negotiation failures from restrictive proxies
			case codes.Unavailable:
				return true
			// DeadlineExceeded: gRPC-level timeout, complementing context.DeadlineExceeded check above
			case codes.DeadlineExceeded:
				return true
			}
		}
		currentErr = errors.Unwrap(currentErr)
	}

	return false
}
