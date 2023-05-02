//go:build !linux

package shared_sock

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// ListenWithSTUNFilter is not supported on other platforms
func ListenWithSTUNFilter(ctx context.Context, port int) (net.PacketConn, error) {
	return nil, fmt.Errorf(fmt.Sprintf("Not supported OS %s. SharedSocket is only supported on Linux", runtime.GOOS))
}

// Listen is not supported on other platforms
func Listen(ctx context.Context, port int, filter BPFFilter) (net.PacketConn, error) {
	return nil, fmt.Errorf(fmt.Sprintf("Not supported OS %s. SharedSocket is only supported on Linux", runtime.GOOS))
}
