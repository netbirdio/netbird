package listener

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

type Listener struct {
	wgIface  lazyconn.WGIface
	peerCfg  lazyconn.PeerConfig
	conn     *net.UDPConn
	endpoint *net.UDPAddr
	done     sync.Mutex
}

func NewListener(wgIface lazyconn.WGIface, cfg lazyconn.PeerConfig, conn *net.UDPConn, addr *net.UDPAddr) (*Listener, error) {
	d := &Listener{
		wgIface:  wgIface,
		peerCfg:  cfg,
		conn:     conn,
		endpoint: addr,
	}
	if err := d.createEndpoint(); err != nil {
		return nil, err
	}
	d.done.Lock()
	return d, nil
}

func (d *Listener) ReadPackets() {
	for {
		buffer := make([]byte, 10)
		n, remoteAddr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Infof("exit from peer listener reader: %v", err)
			break
		}

		if n < 4 {
			log.Warnf("received %d bytes from %s, too short", n, remoteAddr)
			continue
		}
		break
	}

	d.removeEndpoint()
	d.done.Unlock()
}

func (d *Listener) Close() {
	if err := d.conn.Close(); err != nil {
		log.Errorf("failed to close UDP listener: %s", err)
	}
	d.done.Lock()
}

func (d *Listener) removeEndpoint() {
	if err := d.wgIface.RemovePeer(d.peerCfg.PublicKey); err != nil {
		log.Warnf("failed to remove peer listener: %v", err)
	}
}

func (d *Listener) createEndpoint() error {
	return d.wgIface.UpdatePeer(d.peerCfg.PublicKey, d.peerCfg.AllowedIPs, 0, d.endpoint, nil)
}
