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

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/netsweep"
)

func WithCustomDialer(_ bool, _ string) grpc.DialOption {
	return grpc.WithContextDialer(dialContext)
}

// WithSweeper dials like WithCustomDialer but registers connections and
// dials with the sweeper. Append it after WithCustomDialer: gRPC applies
// dial options in order, so the later context dialer wins.
func WithSweeper(sweeper *netsweep.Sweeper) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		dial := sweeper.StartDial(ctx)
		defer dial.Release()

		conn, err := dialContext(dial.Ctx(), addr)
		if err != nil {
			return nil, err
		}
		return dial.WrapConn(conn)
	})
}

func dialContext(ctx context.Context, addr string) (net.Conn, error) {
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
		return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
	}
	return conn, nil
}
