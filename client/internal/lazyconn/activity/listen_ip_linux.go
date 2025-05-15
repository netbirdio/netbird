//go:build !android

package activity

import "net"

var (
	// use this ip to avoid eBPF proxy congestion
	listenIP = net.IP{127, 0, 1, 1}
)
