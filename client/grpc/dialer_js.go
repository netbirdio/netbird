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

// DialHold blocks a dial until it may go. It returns an error when ctx is done.
type DialHold func(ctx context.Context) error

// WithDialHooks is a no-op on WASM/JS: there is no network change signal, no
// TCP socket to tune and no aligned heartbeat to hold dials for.
func WithDialHooks(_ Sweeper, _ *TCPKeepAlive, _ DialHold) grpc.DialOption {
	return grpc.EmptyDialOption{}
}
