package grpc

import (
	"context"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/netevents/sweep"
	"github.com/netbirdio/netbird/util/wsproxy/client"
)

// Sweeper registers in-flight dials for the network change sweep.
type Sweeper interface {
	StartDial(ctx context.Context) *sweep.Dial
}

// WithCustomDialer returns a gRPC dial option that uses WebSocket transport for WASM/JS environments.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
func WithCustomDialer(tlsEnabled bool, component string) grpc.DialOption {
	return client.WithWebSocketDialer(tlsEnabled, component)
}

// WithSweeper is a no-op on WASM/JS: there is no network change signal.
func WithSweeper(_ Sweeper) grpc.DialOption {
	return grpc.EmptyDialOption{}
}
