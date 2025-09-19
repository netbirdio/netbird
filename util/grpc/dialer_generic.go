//go:build !js

package grpc

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func WithCustomDialer(tlsEnabled bool) grpc.DialOption {
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

		conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			log.Errorf("Failed to dial: %s", err)
			return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
		}
		return conn, nil
	})
}
