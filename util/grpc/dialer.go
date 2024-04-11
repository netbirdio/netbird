package grpc

import (
	"context"
	"net"
	"os/user"
	"runtime"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func WithCustomDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		if runtime.GOOS == "linux" {
			currentUser, err := user.Current()
			if err != nil {
				log.Fatalf("failed to get current user: %v", err)
			}

			// the custom dialer requires root permissions which are not required for use cases run as non-root
			if currentUser.Uid != "0" {
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, "tcp", addr)
			}
		}


		conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			log.Errorf("Failed to dial: %s", err)
			return nil, err
		}
		return conn, nil
	})
}
