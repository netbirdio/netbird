package usp

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"

	nbnet "github.com/netbirdio/netbird/util/net"
)

// WGUserSpaceProxy proxies
type WGUserSpaceProxy struct {
	localWGListenPort int
	ctx               context.Context
	cancel            context.CancelFunc

	remoteConn net.Conn
	localConn  net.Conn
	closeMu    sync.Mutex
	closed     bool
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
		return fmt.Errorf("proxy not started")
	}
	p.close()
	return nil
}

func (p *WGUserSpaceProxy) close() {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	// prevent double close
	if p.closed {
		return
	}
	p.closed = true

	p.cancel()

	if err := p.remoteConn.Close(); err != nil {
		log.Warnf("failed to close remote conn: %s", err)
	}

	if err := p.localConn.Close(); err != nil {
		log.Warnf("failed to close conn with WireGuard: %s", err)
	}
}

// proxyToRemote proxies from Wireguard to the RemoteKey
func (p *WGUserSpaceProxy) proxyToRemote() {
	defer p.close()

	buf := make([]byte, 1500)
	for p.ctx.Err() == nil {
		n, err := p.localConn.Read(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Debugf("failed to read from wg interface conn: %s", err)
			return
		}

		_, err = p.remoteConn.Write(buf[:n])
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}

			log.Debugf("failed to write to remote conn: %s", err)
			return
		}
	}
}

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WGUserSpaceProxy) proxyToLocal() {
	defer p.close()

	buf := make([]byte, 1500)
	for p.ctx.Err() == nil {
		n, err := p.remoteConn.Read(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to read from remote conn: %s, %s", p.remoteConn.RemoteAddr(), err)
			return
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
