//go:build !linux

package activity

var (
	listenIP = net.ParseIP("127.0.0.1")
)
