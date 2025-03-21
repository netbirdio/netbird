package activity

import (
	"net"
	"sync"

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

	if err := d.removeEndpoint(); err != nil {
		d.peerCfg.Log.Errorf("failed to remove endpoint: %s", err)
	}

	_ = d.conn.Close() // do not care err because some cases it will return "use of closed network connection"
	d.done.Unlock()
}

func (d *Listener) Close() {
	d.peerCfg.Log.Infof("closing listener: %s", d.conn.LocalAddr().String())
	d.isClosed = true
	if err := d.conn.Close(); err != nil {
		d.peerCfg.Log.Errorf("failed to close UDP listener: %s", err)
	}
	d.done.Lock()
}

func (d *Listener) removeEndpoint() error {
	d.peerCfg.Log.Debugf("removing lazy endpoint: %s", d.endpoint.String())
	return d.wgIface.RemovePeer(d.peerCfg.PublicKey)
}

func (d *Listener) createEndpoint() error {
	d.peerCfg.Log.Debugf("creating lazy endpoint: %s", d.endpoint.String())
	return d.wgIface.UpdatePeer(d.peerCfg.PublicKey, d.peerCfg.AllowedIPs, 0, d.endpoint, nil)
}
