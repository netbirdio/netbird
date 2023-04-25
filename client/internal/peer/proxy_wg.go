package peer

import (
	"context"
	"net"

	log "github.com/sirupsen/logrus"
)

// WireGuardProxy proxies
type WireGuardProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	wgListenAddr string
	remoteKey    string

	remoteConn net.Conn
	localConn  net.Conn
}

func NewWireGuardProxy(wgListenAddr, remoteKey string) *WireGuardProxy {
	p := &WireGuardProxy{
		wgListenAddr: wgListenAddr,
		remoteKey:    remoteKey,
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *WireGuardProxy) Start(remoteConn net.Conn) error {
	p.remoteConn = remoteConn

	var err error
	p.localConn, err = net.Dial("udp", p.wgListenAddr)
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
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
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WireGuardProxy) proxyToRemote() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			log.Debugf("stopped proxying to remote peer %s due to closed connection", p.remoteKey)
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
			log.Debugf("stopped proxying from remote peer %s due to closed connection", p.remoteKey)
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
