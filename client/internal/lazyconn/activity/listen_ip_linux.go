//go:build !android

package activity

import "net"

var (
	// use this ip to avoid eBPF proxy congestion
	listenIP = net.ParseIP("127.0.1.1")
)
