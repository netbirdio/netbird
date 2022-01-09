package proxy

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"net"
)

// WireguardProxy proxies
type WireguardProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	config Config

	remoteConn net.Conn
	localConn  net.Conn
}

func NewWireguardProxy(config Config) *WireguardProxy {
	p := &WireguardProxy{config: config}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *WireguardProxy) updateEndpoint() error {
	// add local proxy connection as a Wireguard peer
	err := iface.UpdatePeer(p.config.WgInterface, p.config.RemoteKey, p.config.AllowedIps, DefaultWgKeepAlive,
		p.localConn.LocalAddr().String(), p.config.PreSharedKey)
	if err != nil {
		return err
	}

	return nil
}

func (p *WireguardProxy) Start(remoteConn net.Conn) error {
	p.remoteConn = remoteConn

	var err error
	p.localConn, err = net.Dial("udp", p.config.WgListenAddr)
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return err
	}

	err = p.updateEndpoint()
	if err != nil {
		log.Errorf("error while updating Wireguard peer endpoint [%s] %v", p.config.RemoteKey, err)
		return err
	}

	go p.proxyToRemote()
	go p.proxyToLocal()

	return nil
}

func (p *WireguardProxy) Close() error {
	p.cancel()
	if c := p.localConn; c != nil {
		err := p.localConn.Close()
		if err != nil {
			return err
		}
	}
	err := iface.RemovePeer(p.config.WgInterface, p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WireguardProxy) proxyToRemote() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			log.Debugf("stopped proxying to remote peer %s due to closed connection", p.config.RemoteKey)
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

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WireguardProxy) proxyToLocal() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.config.RemoteKey)
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
