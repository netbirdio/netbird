package connection

import (
	ice "github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"net"
)

// WgProxy an instance of an instance of the Connection Wireguard Proxy
type WgProxy struct {
	iface      string
	remoteKey  string
	allowedIps string
	wgAddr     string
	close      chan struct{}
	wgConn     net.Conn
}

// NewWgProxy creates a new Connection Wireguard Proxy
func NewWgProxy(iface string, remoteKey string, allowedIps string, wgAddr string) *WgProxy {
	return &WgProxy{
		iface:      iface,
		remoteKey:  remoteKey,
		allowedIps: allowedIps,
		wgAddr:     wgAddr,
		close:      make(chan struct{}),
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

	return nil
}

func (p *WgProxy) StartLocal(host string) error {
	err := iface.UpdatePeer(p.iface, p.remoteKey, p.allowedIps, DefaultWgKeepAlive, host)
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", p.remoteKey, err.Error())
		return err
	}
	return nil
}

// Start starts a new proxy using the ICE connection
func (p *WgProxy) Start(remoteConn *ice.Conn) error {

	wgConn, err := net.Dial("udp", p.wgAddr)
	if err != nil {
		log.Fatalf("failed dialing to local Wireguard port %s", err)
		return err
	}
	p.wgConn = wgConn
	// add local proxy connection as a Wireguard peer
	err = iface.UpdatePeer(p.iface, p.remoteKey, p.allowedIps, DefaultWgKeepAlive,
		wgConn.LocalAddr().String())
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", p.remoteKey, err.Error())
		return err
	}

	go func() { p.proxyToRemotePeer(remoteConn) }()
	go func() { p.proxyToLocalWireguard(remoteConn) }()

	return err
}

// proxyToRemotePeer proxies everything from Wireguard to the remote peer
// blocks
func (p *WgProxy) proxyToRemotePeer(remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.close:
			log.Infof("stopped proxying from remote peer %s due to closed connection", p.remoteKey)
			return
		default:
			n, err := p.wgConn.Read(buf)
			if err != nil {
				//log.Warnln("failed reading from peer: ", err.Error())
				continue
			}

			_, err = remoteConn.Write(buf[:n])
			if err != nil {
				//log.Warnln("failed writing to remote peer: ", err.Error())
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
			log.Infof("stopped proxying from remote peer %s due to closed connection", p.remoteKey)
			return
		default:
			n, err := remoteConn.Read(buf)
			if err != nil {
				//log.Errorf("failed reading from remote connection %s", err)
				continue
			}

			_, err = p.wgConn.Write(buf[:n])
			if err != nil {
				//log.Errorf("failed writing to local Wireguard instance %s", err)
				continue
			}
		}
	}
}
