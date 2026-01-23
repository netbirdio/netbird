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

	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

// ProxyWrapper help to keep the remoteConn instance for net.Conn.Close function call
type ProxyWrapper struct {
	wgeBPFProxy *WGEBPFProxy

	remoteConn net.Conn
	ctx        context.Context
	cancel     context.CancelFunc

	wgRelayedEndpointAddr     *net.UDPAddr
	wgEndpointCurrentUsedAddr *net.UDPAddr

	paused     bool
	pausedCond *sync.Cond
	isStarted  bool

	closeListener *listener.CloseListener
}

func NewProxyWrapper(proxy *WGEBPFProxy) *ProxyWrapper {
	return &ProxyWrapper{
		wgeBPFProxy:   proxy,
		pausedCond:    sync.NewCond(&sync.Mutex{}),
		closeListener: listener.NewCloseListener(),
	}
}
func (p *ProxyWrapper) AddTurnConn(ctx context.Context, endpoint *net.UDPAddr, remoteConn net.Conn) error {
	addr, err := p.wgeBPFProxy.AddTurnConn(remoteConn)
	if err != nil {
		return fmt.Errorf("add turn conn: %w", err)
	}
	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wgRelayedEndpointAddr = addr
	return err
}

func (p *ProxyWrapper) EndpointAddr() *net.UDPAddr {
	return p.wgRelayedEndpointAddr
}

func (p *ProxyWrapper) SetDisconnectListener(disconnected func()) {
	p.closeListener.SetCloseListener(disconnected)
}

func (p *ProxyWrapper) Work() {
	if p.remoteConn == nil {
		return
	}

	p.pausedCond.L.Lock()
	p.paused = false

	p.wgEndpointCurrentUsedAddr = p.wgRelayedEndpointAddr

	if !p.isStarted {
		p.isStarted = true
		go p.proxyToLocal(p.ctx)
	}

	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()
}

func (p *ProxyWrapper) Pause() {
	if p.remoteConn == nil {
		return
	}

	log.Tracef("pause proxy reading from: %s", p.remoteConn.RemoteAddr())
	p.pausedCond.L.Lock()
	p.paused = true
	p.pausedCond.L.Unlock()
}

func (p *ProxyWrapper) RedirectAs(endpoint *net.UDPAddr) {
	p.pausedCond.L.Lock()
	p.paused = false

	if endpoint != nil && endpoint.IP != nil {
		p.wgEndpointCurrentUsedAddr = endpoint
	}

	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()
}

// CloseConn close the remoteConn and automatically remove the conn instance from the map
func (p *ProxyWrapper) CloseConn() error {
	if p.cancel == nil {
		return fmt.Errorf("proxy not started")
	}

	p.cancel()

	p.closeListener.SetCloseListener(nil)

	p.pausedCond.L.Lock()
	p.paused = false
	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()

	if err := p.remoteConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to close remote conn: %w", err)
	}
	return nil
}

func (p *ProxyWrapper) proxyToLocal(ctx context.Context) {
	defer p.wgeBPFProxy.removeTurnConn(uint16(p.wgRelayedEndpointAddr.Port))

	buf := make([]byte, p.wgeBPFProxy.mtu+bufsize.WGBufferOverhead)
	for {
		n, err := p.readFromRemote(ctx, buf)
		if err != nil {
			return
		}

		p.pausedCond.L.Lock()
		for p.paused {
			p.pausedCond.Wait()
		}

		err = p.wgeBPFProxy.sendPkg(buf[:n], p.wgEndpointCurrentUsedAddr)
		p.pausedCond.L.Unlock()

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
			log.Errorf("failed to read from turn conn (endpoint: :%d): %s", p.wgRelayedEndpointAddr.Port, err)
		}
		return 0, err
	}
	return n, nil
}
