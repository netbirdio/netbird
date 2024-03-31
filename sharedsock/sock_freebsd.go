//go:build freebsd

package sharedsock

import (
	"fmt"
	"net"
)

// Listen is not supported yet on FreeBSD
func Listen(port int, filter BPFFilter) (net.PacketConn, error) {
	return nil, fmt.Errorf("SharedSocket is not implemented yet on FreeBSD (https://github.com/netbirdio/netbird/issues/1505)")
}
