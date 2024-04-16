package bind

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

type receiverCreator struct {
	iceBind   *ICEBind
	relayConn net.PacketConn
}

func newReceiverCreator(iceBind *ICEBind) *receiverCreator {
	return &receiverCreator{
		iceBind: iceBind,
	}
}

func (rc *receiverCreator) CreateIPv4ReceiverFn(msgPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) wgConn.ReceiveFunc {
	return rc.iceBind.createIPv4ReceiverFn(msgPool, pc, conn, nil)
}

func (rc *receiverCreator) CreateRelayReceiverFn(msgPool *sync.Pool) wgConn.ReceiveFunc {
	if rc.relayConn == nil {
		log.Debugf("-------rc.conn is nil")
		return nil
	}
	return rc.iceBind.createIPv4ReceiverFn(msgPool, nil, nil, rc.relayConn)
}

func (rc *receiverCreator) setTurnConn(relayConn interface{}) {
	log.Debug("------ SET TURN CONN")
	rc.relayConn = relayConn.(net.PacketConn)
}
