package grpc

import (
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/util/wsproxy/client"
)

// WithCustomDialer returns a gRPC dial option that uses WebSocket transport for WASM/JS environments.
func WithCustomDialer(tlsEnabled bool) grpc.DialOption {
	return client.WithWebSocketDialer(tlsEnabled)
}
