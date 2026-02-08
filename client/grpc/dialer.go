package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"runtime"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

// Backoff returns a backoff configuration for gRPC calls
func Backoff(ctx context.Context) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	b.Clock = backoff.SystemClock
	return backoff.WithContext(b, ctx)
}

// CreateConnection creates a gRPC client connection with the appropriate transport options.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
// When component is provided, WebSocket is used by default for better compatibility.
func CreateConnection(ctx context.Context, addr string, tlsEnabled bool, component string) (*grpc.ClientConn, error) {
	// Use WebSocket by default for management and signal connections (when component is provided)
	// This ensures compatibility with HTTP/1.1-only proxies and restrictive networks
	if runtime.GOOS != "js" && component != "" {
		log.Debugf("Using WebSocket transport for %s (component: %s)", addr, component)
		conn, err := createConnectionWithMode(ctx, addr, tlsEnabled, component, true)
		if err == nil {
			return conn, nil
		}

		// If WebSocket fails, try native gRPC as fallback
		log.Warnf("WebSocket connection failed: %v. Attempting native gRPC fallback...", err)
		nativeConn, nativeErr := createConnectionWithMode(ctx, addr, tlsEnabled, component, false)
		if nativeErr != nil {
			return nil, fmt.Errorf("websocket failed: %v, native gRPC fallback also failed: %w", err, nativeErr)
		}
		return nativeConn, nil
	}

	// For connections without component (or JS runtime), use native gRPC only
	return createConnectionWithMode(ctx, addr, tlsEnabled, component, false)
}

// createConnectionWithMode creates a connection using either native or WebSocket transport
func createConnectionWithMode(ctx context.Context, addr string, tlsEnabled bool, component string, useWebSocket bool) (*grpc.ClientConn, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())

	// For native connections with TLS, set up TLS credentials
	// For WebSocket (wss://), the WebSocket layer handles TLS, so gRPC uses insecure
	if tlsEnabled && runtime.GOOS != "js" && !useWebSocket {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		}))
	}

	// Timeout configuration:
	// - Native gRPC: 10s - shorter timeout to quickly detect ALPN/HTTP2 issues and trigger fallback.
	//   Most successful connections complete within 2-3s; 10s allows for some network variability
	//   while avoiding long waits when proxies block HTTP/2.
	// - WebSocket: 30s - longer timeout since this is the fallback path and we want to give it
	//   the best chance to succeed, especially on high-latency networks.
	timeout := 30 * time.Second
	if !useWebSocket {
		timeout = 10 * time.Second
	}

	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		addr,
		transportOption,
		WithCustomDialer(tlsEnabled, component, useWebSocket),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial context: %w", err)
	}

	return conn, nil
}
