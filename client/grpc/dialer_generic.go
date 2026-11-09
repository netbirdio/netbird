//go:build !js

package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/netevents/sweep"
)

// Sweeper registers in-flight dials for the network change sweep.
type Sweeper interface {
	StartDial(ctx context.Context) *sweep.Dial
}

func WithCustomDialer(_ bool, _ string) grpc.DialOption {
	return grpc.WithContextDialer(dialContext)
}

// WithSweeper dials like WithCustomDialer but registers connections and
// dials with the sweeper. Append it after WithCustomDialer: gRPC applies
// dial options in order, so the later context dialer wins.
func WithSweeper(sweeper Sweeper) grpc.DialOption {
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
	// The custom dialer requires root permissions which are not required for
	// use cases run as non-root. The effective UID is read directly: a passwd
	// lookup fails without cgo for a UID that has no entry, as on OpenShift.
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		log.Debug("Not running as root, using standard dialer")
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, "tcp", addr)
	}

	conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("nbnet.NewDialer().DialContext: %w", err)
	}
	return conn, nil
}
