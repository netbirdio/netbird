package activity

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

	isClosed bool // use to avoid error log when closing the listener
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
	cfg.Log.Infof("created activity listener: %s", addr.String())
	return d, nil
}

func (d *Listener) ReadPackets() {
	d.isClosed = false

	for {
		buffer := make([]byte, 10)
		n, remoteAddr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			if d.isClosed {
				d.peerCfg.Log.Debugf("exit from activity listener")
			} else {
				d.peerCfg.Log.Errorf("failed to read from activity listener: %s", err)
			}
			break
		}

		if n < 4 {
			d.peerCfg.Log.Warnf("received %d bytes from %s, too short", n, remoteAddr)
			continue
		}
		break
	}

	d.removeEndpoint()
	d.done.Unlock()
}

func (d *Listener) Close() {
	d.isClosed = true
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
