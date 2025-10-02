package grpc

import (
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/util/wsproxy/client"
)

// WithCustomDialer returns a gRPC dial option that uses WebSocket transport for WASM/JS environments.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
func WithCustomDialer(tlsEnabled bool, component string) grpc.DialOption {
	return client.WithWebSocketDialer(tlsEnabled, component)
}
