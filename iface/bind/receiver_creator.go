package bind

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

type receiverCreator struct {
	iceBind *ICEBind
}

func newReceiverCreator(iceBind *ICEBind) receiverCreator {
	return receiverCreator{
		iceBind: iceBind,
	}
}

func (rc receiverCreator) CreateIPv4ReceiverFn(msgPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) wgConn.ReceiveFunc {
	return rc.iceBind.createIPv4ReceiverFn(msgPool, pc, conn)
}
