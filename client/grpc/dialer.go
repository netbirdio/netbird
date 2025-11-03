package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

// ErrConnectionShutdown indicates that the connection entered shutdown state before becoming ready
var ErrConnectionShutdown = errors.New("connection shutdown before ready")

// Backoff returns a backoff configuration for gRPC calls
func Backoff(ctx context.Context) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	b.Clock = backoff.SystemClock
	return backoff.WithContext(b, ctx)
}

// waitForConnectionReady blocks until the connection becomes ready or fails.
// Returns an error if the connection times out, is cancelled, or enters shutdown state.
func waitForConnectionReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()

	state := conn.GetState()
	for state != connectivity.Ready && state != connectivity.Shutdown {
		if !conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("wait state change from %s: %w", state, ctx.Err())
		}
		state = conn.GetState()
	}

	if state == connectivity.Shutdown {
		return ErrConnectionShutdown
	}

	return nil
}

// CreateConnection creates a gRPC client connection with the appropriate transport options.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
func CreateConnection(ctx context.Context, addr string, tlsEnabled bool, component string) (*grpc.ClientConn, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())
	// for js, the outer websocket layer takes care of tls
	if tlsEnabled && runtime.GOOS != "js" {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		}))
	}

	conn, err := grpc.NewClient(
		addr,
		transportOption,
		WithCustomDialer(tlsEnabled, component),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := waitForConnectionReady(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
