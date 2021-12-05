package internal

import (
	ice "github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
)

// WgProxy an instance of an instance of the Connection Wireguard Proxy
type WgProxy struct {
	iface        string
	remoteKey    string
	allowedIps   string
	wgAddr       string
	close        chan struct{}
	wgConn       net.Conn
	preSharedKey *wgtypes.Key
}

// NewWgProxy creates a new Connection Wireguard Proxy
func NewWgProxy(iface string, remoteKey string, allowedIps string, wgAddr string, preSharedKey *wgtypes.Key) *WgProxy {
	return &WgProxy{
		iface:        iface,
		remoteKey:    remoteKey,
		allowedIps:   allowedIps,
		wgAddr:       wgAddr,
		close:        make(chan struct{}),
		preSharedKey: preSharedKey,
	}
}

// Close closes the proxy
func (p *WgProxy) Close() error {

	close(p.close)
	if c := p.wgConn; c != nil {
		err := p.wgConn.Close()
		if err != nil {
			return err
		}
	}
	err := iface.RemovePeer(p.iface, p.remoteKey)
	if err != nil {
		return err
	}

	return nil
}

// StartLocal configure the interface with a peer using a direct IP:Port endpoint to the remote host
func (p *WgProxy) StartLocal(host string) error {
	err := iface.UpdatePeer(p.iface, p.remoteKey, p.allowedIps, DefaultWgKeepAlive, host, p.preSharedKey)
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", p.remoteKey, err.Error())
		return err
	}
	return nil
}

// Start starts a new proxy using the ICE connection
func (p *WgProxy) Start(remoteConn *ice.Conn) error {

	/*wgConn, err := net.Dial("udp", p.wgAddr)
	if err != nil {
		log.Fatalf("failed dialing to local Wireguard port %s", err)
		return err
	}
	p.wgConn = wgConn*/
	// add local proxy connection as a Wireguard peer
	err := iface.UpdatePeer(p.iface, p.remoteKey, p.allowedIps, DefaultWgKeepAlive,
		remoteConn.RemoteAddr().String(), p.preSharedKey)
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", p.remoteKey, err.Error())
		return err
	}

	/*go func() { p.proxyToRemotePeer(remoteConn) }()
	go func() { p.proxyToLocalWireguard(remoteConn) }()*/

	return err
}

// proxyToRemotePeer proxies everything from Wireguard to the remote peer
// blocks
func (p *WgProxy) proxyToRemotePeer(remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.close:
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.remoteKey)
			return
		default:
			n, err := p.wgConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = remoteConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}

// proxyToLocalWireguard proxies everything from the remote peer to local Wireguard
// blocks
func (p *WgProxy) proxyToLocalWireguard(remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.close:
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.remoteKey)
			return
		default:
			n, err := remoteConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = p.wgConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}
