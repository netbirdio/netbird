package usp

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/errors"
)

// WGUserSpaceProxy proxies
type WGUserSpaceProxy struct {
	localWGListenPort int

	remoteConn net.Conn
	localConn  net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	closeMu    sync.Mutex
	closed     bool

	pausedMu  sync.Mutex
	paused    bool
	isStarted bool
}

// NewWGUserSpaceProxy instantiate a user space WireGuard proxy. This is not a thread safe implementation
func NewWGUserSpaceProxy(wgPort int) *WGUserSpaceProxy {
	log.Debugf("Initializing new user space proxy with port %d", wgPort)
	p := &WGUserSpaceProxy{
		localWGListenPort: wgPort,
	}
	return p
}

// AddTurnConn
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
func (p *WGUserSpaceProxy) AddTurnConn(ctx context.Context, remoteConn net.Conn) error {
	dialer := net.Dialer{}
	localConn, err := dialer.DialContext(ctx, "udp", fmt.Sprintf(":%d", p.localWGListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		p.cancel()
		return err
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.localConn = localConn
	p.remoteConn = remoteConn

	return err
}

func (p *WGUserSpaceProxy) EndpointAddr() *net.UDPAddr {
	if p.localConn == nil {
		return nil
	}
	endpointUdpAddr, _ := net.ResolveUDPAddr(p.localConn.LocalAddr().Network(), p.localConn.LocalAddr().String())
	return endpointUdpAddr
}

// Work starts the proxy or resumes it if it was paused
func (p *WGUserSpaceProxy) Work() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = false
	p.pausedMu.Unlock()

	if !p.isStarted {
		p.isStarted = true
		go p.proxyToRemote(p.ctx)
		go p.proxyToLocal(p.ctx)
	}
}

// Pause pauses the proxy from receiving data from the remote peer
func (p *WGUserSpaceProxy) Pause() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = true
	p.pausedMu.Unlock()
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

	var result *multierror.Error
	if err := p.remoteConn.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("remote conn: %s", err))
	}

	if err := p.localConn.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("local conn: %s", err))
	}
	return errors.FormatErrorOrNil(result)
}

// proxyToRemote proxies from Wireguard to the RemoteKey
func (p *WGUserSpaceProxy) proxyToRemote(ctx context.Context) {
	defer func() {
		if err := p.close(); err != nil {
			log.Warnf("error in proxy to remote loop: %s", err)
		}
	}()

	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, err := p.localConn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Debugf("failed to read from wg interface conn: %s", err)
			return
		}

		_, err = p.remoteConn.Write(buf[:n])
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			log.Debugf("failed to write to remote conn: %s", err)
			return
		}
	}
}

// proxyToLocal proxies from the Remote peer to local WireGuard
// if the proxy is paused it will drain the remote conn and drop the packets
func (p *WGUserSpaceProxy) proxyToLocal(ctx context.Context) {
	defer func() {
		if err := p.close(); err != nil {
			log.Warnf("error in proxy to local loop: %s", err)
		}
	}()

	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		for {
			n, err := p.remoteConn.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Errorf("failed to read from remote conn: %s, %s", p.remoteConn.RemoteAddr(), err)
				return
			}

			p.pausedMu.Lock()
			if p.paused {
				p.pausedMu.Unlock()
				continue
			}

			_, err = p.localConn.Write(buf[:n])
			p.pausedMu.Unlock()

			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Debugf("failed to write to wg interface conn: %s", err)
				continue
			}
		}
	}
}
