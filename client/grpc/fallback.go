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

// fallbackCodes are gRPC status codes that indicate connection-layer failures
// typically caused by ALPN stripping or HTTP/2 blocking proxies.
var fallbackCodes = map[codes.Code]bool{
	// Unavailable: connection refused, DNS failures, or transport-layer issues
	// including ALPN negotiation failures from restrictive proxies
	codes.Unavailable: true,
	// DeadlineExceeded: gRPC-level timeout, complementing context.DeadlineExceeded check
	codes.DeadlineExceeded: true,
}

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

	// status.FromError traverses the error chain internally, so no manual unwrapping needed
	if s, ok := status.FromError(err); ok {
		return fallbackCodes[s.Code()]
	}

	return false
}
