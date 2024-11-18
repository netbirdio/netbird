package bind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bind"
)

type ProxyBind struct {
	Bind *bind.ICEBind

	wgAddr     *net.UDPAddr
	wgEndpoint *bind.Endpoint
	remoteConn net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	closeMu    sync.Mutex
	closed     bool

	pausedMu  sync.Mutex
	paused    bool
	isStarted bool
}

// AddTurnConn adds a new connection to the bind.
// endpoint is the NetBird address of the remote peer. The SetEndpoint return with the address what will be used in the
// WireGuard configuration.
func (p *ProxyBind) AddTurnConn(ctx context.Context, nbAddr *net.UDPAddr, remoteConn net.Conn) error {
	addr, err := p.Bind.SetEndpoint(nbAddr, remoteConn)
	if err != nil {
		return err
	}

	p.wgAddr = addr
	p.wgEndpoint = addrToEndpoint(addr)
	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	return err

}
func (p *ProxyBind) EndpointAddr() *net.UDPAddr {
	return p.wgAddr
}

func (p *ProxyBind) Work() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = false
	p.pausedMu.Unlock()

	// Start the proxy only once
	if !p.isStarted {
		p.isStarted = true
		go p.proxyToLocal(p.ctx)
	}
}

func (p *ProxyBind) Pause() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = true
	p.pausedMu.Unlock()
}

func (p *ProxyBind) CloseConn() error {
	if p.cancel == nil {
		return fmt.Errorf("proxy not started")
	}
	return p.close()
}

func (p *ProxyBind) close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	p.cancel()

	p.Bind.RemoveEndpoint(p.wgAddr)

	if rErr := p.remoteConn.Close(); rErr != nil && !errors.Is(rErr, net.ErrClosed) {
		return rErr
	}
	return nil
}

func (p *ProxyBind) proxyToLocal(ctx context.Context) {
	defer func() {
		if err := p.close(); err != nil {
			log.Warnf("failed to close remote conn: %s", err)
		}
	}()

	for {
		buf := make([]byte, 1500)
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

		msg := bind.RecvMessage{
			Endpoint: p.wgEndpoint,
			Buffer:   buf[:n],
		}
		p.Bind.RecvChan <- msg
		p.pausedMu.Unlock()
	}
}

func addrToEndpoint(addr *net.UDPAddr) *bind.Endpoint {
	ip, _ := netip.AddrFromSlice(addr.IP.To4())
	addrPort := netip.AddrPortFrom(ip, uint16(addr.Port))
	return &bind.Endpoint{AddrPort: addrPort}
}
