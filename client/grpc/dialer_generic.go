//go:build !js

package grpc

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// WithCustomDialer returns a gRPC dial option with the appropriate dialer.
// If useWebSocket is true, it uses WebSocket transport for environments with HTTP/2 restrictions.
func WithCustomDialer(tlsEnabled bool, component string, useWebSocket bool) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		// Use WebSocket transport if requested
		if useWebSocket && component != "" {
			return dialWebSocket(ctx, addr, tlsEnabled, component)
		}

		// Use native TCP connection
		return dialNative(ctx, addr)
	})
}

// dialWebSocket establishes a WebSocket connection and wraps it as net.Conn
func dialWebSocket(ctx context.Context, addr string, tlsEnabled bool, component string) (net.Conn, error) {
	scheme := "ws"
	if tlsEnabled {
		scheme = "wss"
	}
	u := fmt.Sprintf("%s://%s%s%s", scheme, addr, wsproxy.ProxyPath, component)

	log.Debugf("Dialing via WebSocket: %s", u)

	c, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	// Use context.Background() because the dialer context is cancelled after dial returns
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// dialNative establishes a native TCP connection.
// On Linux, nbnet.NewDialer() requires root privileges to bind to specific network interfaces
// and set socket options for the NetBird tunnel. Non-root users fall back to the standard dialer,
// which works for management/signal connections but may not route traffic through the tunnel.
func dialNative(ctx context.Context, addr string) (net.Conn, error) {
	if runtime.GOOS == "linux" {
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %w", err)
		}

		if currentUser.Uid != "0" {
			log.Debug("Not running as root, using standard dialer")
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp", addr)
		}
	}

	conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
	}
	return conn, nil
}
