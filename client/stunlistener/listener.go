package stunlistener

import (
	"net"

	"github.com/pion/stun"
)

// STUNMsgHandler is a function that handles STUN packets
type STUNMsgHandler func(msg *stun.Message, addr net.Addr) error

// STUNListener is an interface of any STUN packet listener that applies the STUNMsgHandler func
type STUNListener interface {
	net.PacketConn
	Listen(handler STUNMsgHandler) error
}
