package proxy

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
)

// WireguardProxy proxies
type WireguardProxy struct {
	remote string
	ctx    context.Context
	cancel context.CancelFunc

	wgAddr       string
	wgInterface  string
	allowedIps   string
	preSharedKey *wgtypes.Key

	remoteConn net.Conn
	localConn  net.Conn
}

func NewWireguardProxy(remote string) *WireguardProxy {
	p := &WireguardProxy{remote: remote}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *WireguardProxy) updateEndpoint() error {
	// add local proxy connection as a Wireguard peer
	err := iface.UpdatePeer(p.wgInterface, p.remote, p.allowedIps, DefaultWgKeepAlive,
		p.localConn.LocalAddr().String(), p.preSharedKey)
	if err != nil {
		return err
	}

	return nil
}

func (p *WireguardProxy) Start(remoteConn net.Conn) error {
	p.remoteConn = remoteConn

	var err error
	p.localConn, err = net.Dial("udp", p.wgAddr)
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return err
	}

	err = p.updateEndpoint()
	if err != nil {
		log.Errorf("error while updating Wireguard peer endpoint [%s] %v", p.remote, err)
		return err
	}

	go p.proxyToRemote()
	go p.proxyToLocal()

	return nil
}

func (p *WireguardProxy) Close() error {
	p.cancel()
	return nil
}

// proxyToRemote proxies everything from Wireguard to the remote peer
// blocks
func (p *WireguardProxy) proxyToRemote() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.remote)
			return
		default:
			n, err := p.localConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = p.remoteConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}

// proxyToLocal proxies everything from the remote peer to local Wireguard
// blocks
func (p *WireguardProxy) proxyToLocal() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.remoteConn)
			return
		default:
			n, err := p.remoteConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = p.localConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}
