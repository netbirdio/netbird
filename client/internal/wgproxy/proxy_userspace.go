package wgproxy

import (
	"context"
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"
)

// WGUserSpaceProxy proxies
type WGUserSpaceProxy struct {
	localWGListenPort int
	ctx               context.Context
	cancel            context.CancelFunc

	remoteConn net.Conn
	localConn  net.Conn
}

// NewWGUserSpaceProxy instantiate a user space WireGuard proxy
func NewWGUserSpaceProxy(ctx context.Context, wgPort int) *WGUserSpaceProxy {
	log.Debugf("Initializing new user space proxy with port %d", wgPort)
	p := &WGUserSpaceProxy{
		localWGListenPort: wgPort,
	}
	p.ctx, p.cancel = context.WithCancel(ctx)
	return p
}

// AddTurnConn start the proxy with the given remote conn
func (p *WGUserSpaceProxy) AddTurnConn(remoteConn net.Conn) (net.Addr, error) {
	p.remoteConn = remoteConn

	var err error
	dialer := &net.Dialer{}
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
	p.cancel()
	if p.localConn == nil {
		return nil
	}

	if p.remoteConn == nil {
		return nil
	}

	if err := p.remoteConn.Close(); err != nil {
		log.Warnf("failed to close remote conn: %s", err)
	}
	return p.localConn.Close()
}

// Free doing nothing because this implementation of proxy does not have global state
func (p *WGUserSpaceProxy) Free() error {
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WGUserSpaceProxy) proxyToRemote() {
	defer log.Infof("exit from proxyToRemote: %s", p.localConn.LocalAddr())

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := p.localConn.Read(buf)
			if err != nil {
				log.Debugf("failed to read from wg interface conn: %s", err)
				continue
			}

			_, err = p.remoteConn.Write(buf[:n])
			if err != nil {
				if err == io.EOF {
					p.cancel()
				} else {
					log.Debugf("failed to write to remote conn: %s", err)
				}
				continue
			}
		}
	}
}

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WGUserSpaceProxy) proxyToLocal() {
	defer p.cancel()
	defer log.Infof("exit from proxyToLocal: %s", p.localConn.LocalAddr())
	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := p.remoteConn.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Errorf("failed to read from remote conn: %s", err)
				continue
			}

			_, err = p.localConn.Write(buf[:n])
			if err != nil {
				log.Debugf("failed to write to wg interface conn: %s", err)
				continue
			}
		}
	}
}
