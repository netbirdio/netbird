//go:build linux && !android

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

// ProxyWrapper help to keep the remoteConn instance for net.Conn.Close function call
type ProxyWrapper struct {
	WgeBPFProxy *WGEBPFProxy

	remoteConn net.Conn
	ctx        context.Context
	cancel     context.CancelFunc

	wgEndpointAddr *net.UDPAddr

	pausedMu  sync.Mutex
	paused    bool
	isStarted bool

	closeListener *listener.CloseListener
}

func NewProxyWrapper(WgeBPFProxy *WGEBPFProxy) *ProxyWrapper {
	return &ProxyWrapper{
		WgeBPFProxy:   WgeBPFProxy,
		closeListener: listener.NewCloseListener(),
	}
}

func (p *ProxyWrapper) AddTurnConn(ctx context.Context, endpoint *net.UDPAddr, remoteConn net.Conn) error {
	addr, err := p.WgeBPFProxy.AddTurnConn(remoteConn)
	if err != nil {
		return fmt.Errorf("add turn conn: %w", err)
	}
	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wgEndpointAddr = addr
	return err
}

func (p *ProxyWrapper) EndpointAddr() *net.UDPAddr {
	return p.wgEndpointAddr
}

func (p *ProxyWrapper) SetDisconnectListener(disconnected func()) {
	p.closeListener.SetCloseListener(disconnected)
}

func (p *ProxyWrapper) Work() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = false
	p.pausedMu.Unlock()

	if !p.isStarted {
		p.isStarted = true
		go p.proxyToLocal(p.ctx)
	}
}

func (p *ProxyWrapper) Pause() {
	if p.remoteConn == nil {
		return
	}

	log.Tracef("pause proxy reading from: %s", p.remoteConn.RemoteAddr())
	p.pausedMu.Lock()
	p.paused = true
	p.pausedMu.Unlock()
}

// CloseConn close the remoteConn and automatically remove the conn instance from the map
func (e *ProxyWrapper) CloseConn() error {
	if e.cancel == nil {
		return fmt.Errorf("proxy not started")
	}

	e.cancel()

	if err := e.remoteConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to close remote conn: %w", err)
	}
	return nil
}

func (p *ProxyWrapper) proxyToLocal(ctx context.Context) {
	defer p.WgeBPFProxy.removeTurnConn(uint16(p.wgEndpointAddr.Port))

	buf := make([]byte, 1500)
	for {
		n, err := p.readFromRemote(ctx, buf)
		if err != nil {
			return
		}

		p.pausedMu.Lock()
		if p.paused {
			p.pausedMu.Unlock()
			continue
		}

		err = p.WgeBPFProxy.sendPkg(buf[:n], p.wgEndpointAddr.Port)
		p.pausedMu.Unlock()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("failed to write out turn pkg to local conn: %v", err)
		}
	}
}

func (p *ProxyWrapper) readFromRemote(ctx context.Context, buf []byte) (int, error) {
	n, err := p.remoteConn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		p.closeListener.Notify()
		if !errors.Is(err, io.EOF) {
			log.Errorf("failed to read from turn conn (endpoint: :%d): %s", p.wgEndpointAddr.Port, err)
		}
		return 0, err
	}
	return n, nil
}
