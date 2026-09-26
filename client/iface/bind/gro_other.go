//go:build !linux

package bind

import "net"

func disableUDPGRO(_ *net.UDPConn) error {
	return nil
}
