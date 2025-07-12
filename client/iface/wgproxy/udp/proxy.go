package udp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	cerrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

// WGUDPProxy proxies
type WGUDPProxy struct {
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

	closeListener *listener.CloseListener
}

// NewWGUDPProxy instantiate a UDP based WireGuard proxy. This is not a thread safe implementation
func NewWGUDPProxy(wgPort int) *WGUDPProxy {
	log.Debugf("Initializing new user space proxy with port %d", wgPort)
	p := &WGUDPProxy{
		localWGListenPort: wgPort,
		closeListener:     listener.NewCloseListener(),
	}
	return p
}

// AddTurnConn
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
func (p *WGUDPProxy) AddTurnConn(ctx context.Context, endpoint *net.UDPAddr, remoteConn net.Conn) error {
	dialer := net.Dialer{}
	localConn, err := dialer.DialContext(ctx, "udp", fmt.Sprintf(":%d", p.localWGListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return err
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.localConn = localConn
	p.remoteConn = remoteConn

	return err
}

func (p *WGUDPProxy) EndpointAddr() *net.UDPAddr {
	if p.localConn == nil {
		return nil
	}
	endpointUdpAddr, _ := net.ResolveUDPAddr(p.localConn.LocalAddr().Network(), p.localConn.LocalAddr().String())
	return endpointUdpAddr
}

func (p *WGUDPProxy) SetDisconnectListener(disconnected func()) {
	p.closeListener.SetCloseListener(disconnected)
}

// Work starts the proxy or resumes it if it was paused
func (p *WGUDPProxy) Work() {
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
func (p *WGUDPProxy) Pause() {
	if p.remoteConn == nil {
		return
	}

	p.pausedMu.Lock()
	p.paused = true
	p.pausedMu.Unlock()
}

// CloseConn close the localConn
func (p *WGUDPProxy) CloseConn() error {
	if p.cancel == nil {
		return fmt.Errorf("proxy not started")
	}
	return p.close()
}

func (p *WGUDPProxy) close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	// prevent double close
	if p.closed {
		return nil
	}

	p.closeListener.SetCloseListener(nil)
	p.closed = true

	p.cancel()

	var result *multierror.Error
	if err := p.remoteConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		result = multierror.Append(result, fmt.Errorf("remote conn: %s", err))
	}

	if err := p.localConn.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("local conn: %s", err))
	}
	return cerrors.FormatErrorOrNil(result)
}

// proxyToRemote proxies from Wireguard to the RemoteKey
func (p *WGUDPProxy) proxyToRemote(ctx context.Context) {
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
			p.closeListener.Notify()
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
func (p *WGUDPProxy) proxyToLocal(ctx context.Context) {
	defer func() {
		if err := p.close(); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warnf("error in proxy to local loop: %s", err)
			}
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, err := p.remoteConnRead(ctx, buf)
		if err != nil {
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

func (p *WGUDPProxy) remoteConnRead(ctx context.Context, buf []byte) (n int, err error) {
	n, err = p.remoteConn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Errorf("failed to read from remote conn: %s, %s", p.remoteConn.LocalAddr(), err)
		return
	}
	return
}
