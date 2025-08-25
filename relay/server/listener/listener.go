package listener

import (
	"context"
	"net"

	"github.com/netbirdio/netbird/relay/protocol"
)

type Listener interface {
	Listen(func(conn net.Conn)) error
	Shutdown(ctx context.Context) error
	Protocol() protocol.Protocol
}
