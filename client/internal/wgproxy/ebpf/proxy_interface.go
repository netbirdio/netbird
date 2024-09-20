package ebpf

import (
	"context"
	"net"
)

type (
	Proxy interface {
		Free() error
		AddTurnConn(ctx context.Context, conn net.Conn) (net.Addr, error)
	}
)
