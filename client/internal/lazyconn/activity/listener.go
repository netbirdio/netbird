package activity

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

// Listener it is not a thread safe implementation, do not call Close before ReadPackets. It will cause blocking
type Listener struct {
	wgIface  lazyconn.WGIface
	peerCfg  lazyconn.PeerConfig
	conn     *net.UDPConn
	endpoint *net.UDPAddr
	done     sync.Mutex

	isClosed bool // use to avoid error log when closing the listener
}

func NewListener(wgIface lazyconn.WGIface, cfg lazyconn.PeerConfig) (*Listener, error) {
	d := &Listener{
		wgIface: wgIface,
		peerCfg: cfg,
	}

	conn, err := d.newConn()
	if err != nil {
		return nil, err
	}
	d.conn = conn
	d.endpoint = conn.LocalAddr().(*net.UDPAddr)

	if err := d.createEndpoint(); err != nil {
		return nil, err
	}
	d.done.Lock()
	cfg.Log.Infof("created activity listener: %s", conn.LocalAddr().(*net.UDPAddr).String())
	return d, nil
}

func (d *Listener) ReadPackets() {
	for {
		n, remoteAddr, err := d.conn.ReadFromUDP(make([]byte, 1))
		if err != nil {
			if d.isClosed {
				d.peerCfg.Log.Debugf("exit from activity listener")
			} else {
				d.peerCfg.Log.Errorf("failed to read from activity listener: %s", err)
			}
			break
		}

		if n < 1 {
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

func (d *Listener) newConn() (*net.UDPConn, error) {
	addr := &net.UDPAddr{
		Port: 0,
		IP:   listenIP,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Errorf("failed to listen on %s: %s", addr, err)
		return nil, err
	}

	return conn, nil
}
