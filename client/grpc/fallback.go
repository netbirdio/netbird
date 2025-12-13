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

// ShouldFallbackToWebSocket checks if the error indicates we should try WebSocket
func ShouldFallbackToWebSocket(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded (wrapped or unwrapped)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Unwrap to find the gRPC status error
	var currentErr error = err
	for currentErr != nil {
		if s, ok := status.FromError(currentErr); ok {
			switch s.Code() {
			case codes.Unavailable, codes.Internal, codes.DeadlineExceeded:
				return true
			}
		}
		currentErr = errors.Unwrap(currentErr)
	}

	return false
}
