package grpc

import (
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/util/wsproxy/client"
)

// WithCustomDialer returns a gRPC dial option that uses WebSocket transport for WASM/JS environments.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
// The useWebSocket parameter is ignored in JS builds as WebSocket is always used.
func WithCustomDialer(tlsEnabled bool, component string, _ bool) grpc.DialOption {
	return client.WithWebSocketDialer(tlsEnabled, component)
}

// Fallback functions are no-ops for JS builds since WebSocket is always used

// EnableWebSocketFallback is a no-op for JS builds
func EnableWebSocketFallback() {
	// No-op: JS/WASM builds always use WebSocket transport
}

// IsWebSocketFallbackEnabled always returns true for JS builds
func IsWebSocketFallbackEnabled() bool { return true }

// ShouldFallbackToWebSocket always returns false for JS builds (no fallback needed)
func ShouldFallbackToWebSocket(_ error) bool { return false }
