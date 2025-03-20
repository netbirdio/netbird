//go:build !linux || android

package activity

import "net"

var (
	listenIP = net.ParseIP("127.0.0.1")
)
