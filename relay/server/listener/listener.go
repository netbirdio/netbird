package listener

import (
	"context"
	"net"
)

type Listener interface {
	Listen(func(conn net.Conn)) error
	Shutdown(ctx context.Context) error
}
