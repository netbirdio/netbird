package listener

import (
	"context"
	"net"
)

type Listener interface {
	Listen(func(conn net.Conn)) error
	Close(ctx context.Context) error
}
