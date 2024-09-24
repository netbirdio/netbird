package usp

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
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
	dialer := net.Dialer{}
	p.localConn, err = dialer.DialContext(p.ctx, "udp", fmt.Sprintf(":%d", p.localWGListenPort))
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
	return p.close()
}

func (p *WGUserSpaceProxy) close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	// prevent double close
	if p.closed {
		return nil
	}
	p.closed = true

	p.cancel()

	var result error
	if err := p.remoteConn.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("remote conn: %s", err))
	}

	if err := p.localConn.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("local conn: %s", err))
	}
	return result
}

// proxyToRemote proxies from Wireguard to the RemoteKey
func (p *WGUserSpaceProxy) proxyToRemote() {
	defer func() {
		if err := p.close(); err != nil {
			log.Warnf("error in proxy to remote loop: %s", err)
		}
	}()

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

// proxyToLocal proxies from the Remote peer to local WireGuard
func (p *WGUserSpaceProxy) proxyToLocal() {
	defer func() {
		if err := p.close(); err != nil {
			log.Warnf("error in proxy to local loop: %s", err)
		}
	}()

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
