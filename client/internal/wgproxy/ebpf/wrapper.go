//go:build linux && !android

package ebpf

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ProxyWrapper help to keep the remoteConn instance for net.Conn.Close function call
type ProxyWrapper struct {
	WgeBPFProxy *WGEBPFProxy

	remoteConn net.Conn
	ctx        context.Context
	cancel     context.CancelFunc

	wgEndpointPort uint16

	pausedMu  sync.Mutex
	paused    bool
	isStarted bool
}

func (p *ProxyWrapper) AddTurnConn(ctx context.Context, remoteConn net.Conn) (net.Addr, error) {
	addr, err := p.WgeBPFProxy.AddTurnConn(remoteConn)
	if err != nil {
		return nil, fmt.Errorf("add turn conn: %w", err)
	}
	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wgEndpointPort = uint16(addr.Port)
	return addr, err
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

	p.pausedMu.Lock()
	p.paused = true
	p.pausedMu.Unlock()
}

func (p *ProxyWrapper) Resume() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = false
	p.pausedMu.Unlock()
}

// CloseConn close the remoteConn and automatically remove the conn instance from the map
func (e *ProxyWrapper) CloseConn() error {
	if e.cancel == nil {
		return fmt.Errorf("proxy not started")
	}

	e.cancel()

	if err := e.remoteConn.Close(); err != nil {
		return fmt.Errorf("failed to close remote conn: %w", err)
	}
	return nil
}

func (p *ProxyWrapper) proxyToLocal(ctx context.Context) {
	defer p.WgeBPFProxy.removeTurnConn(p.wgEndpointPort)

	var (
		err error
		n   int
	)
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, err = p.remoteConn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if err != io.EOF {
				log.Errorf("failed to read from turn conn (endpoint: :%d): %s", p.wgEndpointPort, err)
			}
			return
		}

		if err := p.WgeBPFProxy.sendPkg(buf[:n], p.wgEndpointPort); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("failed to write out turn pkg to local conn: %v", err)
		}
	}
}
