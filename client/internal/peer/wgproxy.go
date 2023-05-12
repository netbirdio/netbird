package peer

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
)

// WireGuardProxy proxies
type WireGuardProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	wgListenPort int
	remoteKey    string

	remoteConn net.Conn
	localConn  net.Conn
}

func NewWireGuardProxy(wgListenPort int, remoteKey string, remoteConn net.Conn) *WireGuardProxy {
	p := &WireGuardProxy{
		wgListenPort: wgListenPort,
		remoteKey:    remoteKey,
		remoteConn:   remoteConn,
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *WireGuardProxy) Start() (net.Addr, error) {
	lConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", p.wgListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}
	p.localConn = lConn

	go p.proxyToRemote()
	go p.proxyToLocal()

	return lConn.LocalAddr(), nil
}

func (p *WireGuardProxy) Close() error {
	p.cancel()
	if p.localConn != nil {
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
