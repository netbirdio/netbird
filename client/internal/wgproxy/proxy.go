package wgproxy

import (
	"context"
	"net"
)

// Proxy is a transfer layer between the relayed connection and the WireGuard
type Proxy interface {
	AddTurnConn(ctx context.Context, turnConn net.Conn) (net.Addr, error)
	Work()
	Pause()
	CloseConn() error
}
