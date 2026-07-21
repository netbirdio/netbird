//go:build !linux && !darwin && !freebsd

package ipcauth

import (
	"fmt"
	"net"
	"runtime"
)

// PeerIdentity is unimplemented on platforms without a Unix-socket peer-credential
// primitive. Windows derives identity from the named-pipe client token instead
// (see the Windows transport credentials), so it never calls this.
func PeerIdentity(net.Conn) (Identity, error) {
	return Identity{}, fmt.Errorf("peer credential check not supported on %s", runtime.GOOS)
}
