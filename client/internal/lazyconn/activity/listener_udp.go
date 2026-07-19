package activity

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

// UDPListener uses UDP sockets for activity detection in kernel mode.
type UDPListener struct {
	wgIface  WgInterface
	peerCfg  lazyconn.PeerConfig
	conn     *net.UDPConn
	endpoint *net.UDPAddr
	done     sync.Mutex

	isClosed atomic.Bool

	capturedPacket []byte
}

// NewUDPListener creates a listener that detects activity via UDP socket reads.
func NewUDPListener(wgIface WgInterface, cfg lazyconn.PeerConfig) (*UDPListener, error) {
	d := &UDPListener{
		wgIface: wgIface,
		peerCfg: cfg,
	}

	conn, err := d.newConn()
	if err != nil {
		return nil, fmt.Errorf("create UDP connection: %v", err)
	}
	d.conn = conn
	d.endpoint = conn.LocalAddr().(*net.UDPAddr)

	if err := d.createEndpoint(); err != nil {
		return nil, err
	}

	d.done.Lock()
	cfg.Log.Infof("created activity listener: %s", d.conn.LocalAddr().(*net.UDPAddr).String())
	return d, nil
}

// ReadPackets blocks reading from the UDP socket until activity is detected or the listener is closed.
// The first packet that triggers activity is captured so it can be reinjected through the real
// transport once it is established. Without this, kernel WireGuard's handshake initiation would be
// dropped and WG would only retry after REKEY_TIMEOUT.
func (d *UDPListener) ReadPackets() {
	for {
		buf := make([]byte, int(d.wgIface.MTU())+bufsize.WGBufferOverhead)
		n, remoteAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if d.isClosed.Load() {
				d.peerCfg.Log.Infof("exit from activity listener")
			} else {
				d.peerCfg.Log.Errorf("failed to read from activity listener: %s", err)
			}
			break
		}

		if n < 1 {
			d.peerCfg.Log.Warnf("received %d bytes from %s, too short", n, remoteAddr)
			continue
		}
		d.capturedPacket = slices.Clone(buf[:n])
		d.peerCfg.Log.Infof("activity detected, captured %d bytes for reinjection", n)
		break
	}

	// Leave the peer in place. ConfigureWGEndpoint will UpdatePeer with the real endpoint;
	// removing the peer here wipes kernel WG's staged queue and drops the user packet that
	// triggered activation.
	_ = d.conn.Close()
	d.done.Unlock()
}

// CapturedPacket returns the first packet that triggered activity, or nil if none was captured.
// Safe to call after ReadPackets returns.
func (d *UDPListener) CapturedPacket() []byte {
	return d.capturedPacket
}

// Close stops the listener and cleans up resources.
func (d *UDPListener) Close() {
	d.peerCfg.Log.Infof("closing activity listener: %s", d.conn.LocalAddr().String())
	d.isClosed.Store(true)

	if err := d.conn.Close(); err != nil {
		d.peerCfg.Log.Errorf("failed to close UDP listener: %s", err)
	}
	d.done.Lock()
}

func (d *UDPListener) createEndpoint() error {
	d.peerCfg.Log.Debugf("creating lazy endpoint: %s", d.endpoint.String())
	return d.wgIface.IdlePeerEndpoint(d.peerCfg.PublicKey, d.peerCfg.AllowedIPs, d.endpoint)
}

func (d *UDPListener) newConn() (*net.UDPConn, error) {
	addr := &net.UDPAddr{
		Port: 0,
		IP:   listenIP,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Errorf("failed to create activity listener on %s: %s", addr, err)
		return nil, err
	}

	return conn, nil
}
