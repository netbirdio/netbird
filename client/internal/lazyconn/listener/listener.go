package listener

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Listener struct {
	peerID wgtypes.Key

	conn *net.UDPConn
	wg   sync.WaitGroup
}

func NewListener(peerID wgtypes.Key, addr *net.UDPAddr) (*Listener, error) {
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	d := &Listener{
		conn:   conn,
		peerID: peerID,
	}
	return d, nil
}

func (d *Listener) ReadPackets(trigger func(peerID wgtypes.Key)) {
	d.wg.Done()
	defer d.wg.Done()

	for {
		buffer := make([]byte, 10)
		n, remoteAddr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Infof("exit from fake peer reader: %v", err)
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
	d.wg.Wait()
}
