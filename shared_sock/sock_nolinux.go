//go:build !linux

package shared_sock

import (
	"fmt"
	"net"
	"runtime"
)

// Listen is not supported on other platforms
func Listen(port int, filter BPFFilter) (net.PacketConn, error) {
	return nil, fmt.Errorf(fmt.Sprintf("Not supported OS %s. SharedSocket is only supported on Linux", runtime.GOOS))
}
