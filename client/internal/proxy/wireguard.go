package proxy

import (
	"context"
	log "github.com/sirupsen/logrus"
	"net"
)

// WireGuardProxy proxies
type WireGuardProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	config Config

	remoteConn net.Conn
	localConn  net.Conn
}

func NewWireGuardProxy(config Config) *WireGuardProxy {
	p := &WireGuardProxy{config: config}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *WireGuardProxy) updateEndpoint() error {
	udpAddr, err := net.ResolveUDPAddr(p.localConn.LocalAddr().Network(), p.localConn.LocalAddr().String())
	if err != nil {
		return err
	}
	// add local proxy connection as a Wireguard peer
	err = p.config.WgInterface.UpdatePeer(p.config.RemoteKey, p.config.AllowedIps, DefaultWgKeepAlive,
		udpAddr, p.config.PreSharedKey)
	if err != nil {
		return err
	}

	return nil
}

func (p *WireGuardProxy) Start(remoteConn net.Conn) error {
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

func (p *WireGuardProxy) Close() error {
	p.cancel()
	if c := p.localConn; c != nil {
		err := p.localConn.Close()
		if err != nil {
			return err
		}
	}
	err := p.config.WgInterface.RemovePeer(p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WireGuardProxy) proxyToRemote() {

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
func (p *WireGuardProxy) proxyToLocal() {

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

func (p *WireGuardProxy) Type() Type {
	return TypeWireGuard
}
