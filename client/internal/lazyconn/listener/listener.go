package listener

import (
	"net"

	log "github.com/sirupsen/logrus"
)

type Listener struct {
	peerID string

	conn *net.UDPConn
}

func NewListener(peerID string, conn *net.UDPConn) *Listener {
	d := &Listener{
		conn:   conn,
		peerID: peerID,
	}
	return d
}

func (d *Listener) ReadPackets(trigger func(peerID string)) {
	for {
		buffer := make([]byte, 10)
		n, remoteAddr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Infof("exit from peer listener reader: %v", err)
			return
		}

		if n < 4 {
			log.Warnf("received %d bytes from %s, too short", n, remoteAddr)
			continue
		}
		trigger(d.peerID)
	}
}

func (d *Listener) Close() {
	if err := d.conn.Close(); err != nil {
		log.Errorf("failed to close UDP listener: %s", err)
	}
}
