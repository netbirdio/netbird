package listener

import "net"

type Listener interface {
	Listen(func(conn net.Conn)) error
	Close() error
	WaitForExitAcceptedConns()
}
