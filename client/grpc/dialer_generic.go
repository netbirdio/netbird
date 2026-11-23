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

// WithDialHooks dials like WithSweeper (a nil sweeper dials plain) and hands
// every dialed connection to keepAlive, which tunes its TCP keepalive when
// the stream on it is confirmed aligned. Append it after WithCustomDialer:
// gRPC applies dial options in order, so the later context dialer wins. Use
// it instead of WithSweeper when a keepAlive is tracked, never both.
func WithDialHooks(sweeper Sweeper, keepAlive *TCPKeepAlive) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		dial := (*sweep.Sweeper)(nil).StartDial(ctx)
		if sweeper != nil {
			dial = sweeper.StartDial(ctx)
		}
		defer dial.Release()

		conn, err := dialContext(dial.Ctx(), addr)
		if err != nil {
			return nil, err
		}
		wrapped, err := dial.WrapConn(conn)
		if err != nil {
			return nil, err
		}
		// Track the raw connection: the sweeper's wrapper hides the TCP
		// socket the keepalive is set on.
		keepAlive.Track(conn)
		return wrapped, nil
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
