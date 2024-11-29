package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"os/user"
	"runtime"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func WithCustomDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		if runtime.GOOS == "linux" {
			currentUser, err := user.Current()
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "failed to get current user: %v", err)
			}

			// the custom dialer requires root permissions which are not required for use cases run as non-root
			if currentUser.Uid != "0" {
				log.Debug("Not running as root, using standard dialer")
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, "tcp", addr)
			}
		}

		log.Debug("Using nbnet.NewDialer()")
		conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			log.Errorf("Failed to dial: %s", err)
			return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
		}
		return conn, nil
	})
}

// grpcDialBackoff is the backoff mechanism for the grpc calls
func Backoff(ctx context.Context) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	b.Clock = backoff.SystemClock
	return backoff.WithContext(b, ctx)
}

func CreateConnection(addr string, tlsEnabled bool) (*grpc.ClientConn, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())

	if tlsEnabled {
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	connCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		addr,
		transportOption,
		WithCustomDialer(),
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
