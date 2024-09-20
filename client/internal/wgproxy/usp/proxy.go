package usp

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

// WGUserSpaceProxy proxies
type WGUserSpaceProxy struct {
	localWGListenPort int
	ctx               context.Context
	cancel            context.CancelFunc

	remoteConn net.Conn
	localConn  net.Conn
}

// NewWGUserSpaceProxy instantiate a user space WireGuard proxy. This is not a thread safe implementation
func NewWGUserSpaceProxy(wgPort int) *WGUserSpaceProxy {
	log.Debugf("Initializing new user space proxy with port %d", wgPort)
	p := &WGUserSpaceProxy{
		localWGListenPort: wgPort,
	}
	return p
}

// AddTurnConn start the proxy with the given remote conn
func (p *WGUserSpaceProxy) AddTurnConn(ctx context.Context, remoteConn net.Conn) (net.Addr, error) {
	p.ctx, p.cancel = context.WithCancel(ctx)

	p.remoteConn = remoteConn

	var err error
	p.localConn, err = nbnet.NewDialer().DialContext(p.ctx, "udp", fmt.Sprintf(":%d", p.localWGListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}

	go p.proxyToRemote()
	go p.proxyToLocal()

	return p.localConn.LocalAddr(), err
}

// CloseConn close the localConn
func (p *WGUserSpaceProxy) CloseConn() error {
	if p.cancel == nil {
		return nil
	}

	p.cancel()

	if err := p.remoteConn.Close(); err != nil {
		log.Warnf("failed to close remote conn: %s", err)
	}
	return p.localConn.Close()
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WGUserSpaceProxy) proxyToRemote() {
	defer log.Infof("exit from proxyToRemote: %s", p.localConn.LocalAddr())
	defer p.cancel()

	buf := make([]byte, 1500)
	for p.ctx.Err() == nil {
		n, err := p.localConn.Read(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Debugf("failed to read from wg interface conn: %s", err)
			continue
		}

		_, err = p.remoteConn.Write(buf[:n])
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}

			log.Debugf("failed to write to remote conn: %s", err)
			continue
		}

	}
}

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WGUserSpaceProxy) proxyToLocal() {
	defer p.cancel()
	defer log.Infof("exit from proxyToLocal: %s", p.localConn.LocalAddr())
	buf := make([]byte, 1500)
	for p.ctx.Err() == nil {
		n, err := p.remoteConn.Read(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to read from remote conn: %s", err)
			continue
		}

		_, err = p.localConn.Write(buf[:n])
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Debugf("failed to write to wg interface conn: %s", err)
			continue
		}
	}
}
