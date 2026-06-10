//go:build !linux && !darwin && !freebsd

package cmd

import (
	"fmt"
	"net"
	"runtime"
)

// peerUID is unimplemented on this platform, so the trust-on-first-use socket
// migration cannot run here. Configure --socket-owner explicitly, or use
// --disable-strict-socket. (Windows uses a TCP socket and never reaches this.)
func peerUID(net.Conn) (int, error) {
	return 0, fmt.Errorf("peer credential check not supported on %s", runtime.GOOS)
}
