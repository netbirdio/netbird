package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		addr,
		transportOption,
		WithCustomDialer(tlsEnabled, component),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		log.Printf("DialContext error: %v", err)
		return nil, err
	}

	return conn, nil
}
