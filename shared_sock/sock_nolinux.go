//go:build !linux

package shared_sock

import "fmt"

func Listen(ctx context.Context, port int) (net.PacketConn, error) {
	return nil, fmt.Errorf(fmt.Sprintf("Not supported OS %s. STUNSocket is only supported on Linux", runtime.GOOS))
}
