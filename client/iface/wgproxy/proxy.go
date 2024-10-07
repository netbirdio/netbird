package wgproxy

import (
	"context"
	"net"
)

// Proxy is a transfer layer between the relayed connection and the WireGuard
type Proxy interface {
	AddTurnConn(ctx context.Context, endpoint *net.UDPAddr, turnConn net.Conn) error
	EndpointAddr() *net.UDPAddr
	Work()
	Pause()
	CloseConn() error
}
