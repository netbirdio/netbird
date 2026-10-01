//go:build !linux || android

package activity

import "net"

var (
	listenIP = net.IP{127, 0, 0, 1}
)
