package bind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

type ProxyBind struct {
	Bind *bind.ICEBind

	fakeNetIP      *netip.AddrPort
	wgBindEndpoint *bind.Endpoint
	remoteConn     net.Conn
	ctx            context.Context
	cancel         context.CancelFunc
	closeMu        sync.Mutex
	closed         bool

	pausedMu  sync.Mutex
	paused    bool
	isStarted bool

	closeListener *listener.CloseListener
}

func NewProxyBind(bind *bind.ICEBind) *ProxyBind {
	p := &ProxyBind{
		Bind:          bind,
		closeListener: listener.NewCloseListener(),
	}

	return p
}

// AddTurnConn adds a new connection to the bind.
// endpoint is the NetBird address of the remote peer. The SetEndpoint return with the address what will be used in the
// WireGuard configuration.
func (p *ProxyBind) AddTurnConn(ctx context.Context, nbAddr *net.UDPAddr, remoteConn net.Conn) error {
	fakeNetIP, err := fakeAddress(nbAddr)
	if err != nil {
		return err
	}

	p.fakeNetIP = fakeNetIP
	p.wgBindEndpoint = &bind.Endpoint{AddrPort: *fakeNetIP}
	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	return nil

}
func (p *ProxyBind) EndpointAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.fakeNetIP.Addr().AsSlice(),
		Port: int(p.fakeNetIP.Port()),
		Zone: p.fakeNetIP.Addr().Zone(),
	}
}

func (p *ProxyBind) SetDisconnectListener(disconnected func()) {
	p.closeListener.SetCloseListener(disconnected)
}

func (p *ProxyBind) Work() {
	if p.remoteConn == nil {
		return
	}

	p.Bind.SetEndpoint(p.fakeNetIP.Addr(), p.remoteConn)

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

	p.closeListener.SetCloseListener(nil)

	p.closed = true

	p.cancel()

	p.Bind.RemoveEndpoint(p.fakeNetIP.Addr())

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
			p.closeListener.Notify()
			log.Errorf("failed to read from remote conn: %s, %s", p.remoteConn.RemoteAddr(), err)
			return
		}

		p.pausedMu.Lock()
		if p.paused {
			p.pausedMu.Unlock()
			continue
		}

		msg := bind.RecvMessage{
			Endpoint: p.wgBindEndpoint,
			Buffer:   buf[:n],
		}
		p.Bind.RecvChan <- msg
		p.pausedMu.Unlock()
	}
}

// fakeAddress returns a fake address that is used to as an identifier for the peer.
// The fake address is in the format of 127.1.x.x where x.x is the last two octets of the peer address.
func fakeAddress(peerAddress *net.UDPAddr) (*netip.AddrPort, error) {
	octets := strings.Split(peerAddress.IP.String(), ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("invalid IP format")
	}

	fakeIP, err := netip.ParseAddr(fmt.Sprintf("127.1.%s.%s", octets[2], octets[3]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse new IP: %w", err)
	}

	netipAddr := netip.AddrPortFrom(fakeIP, uint16(peerAddress.Port))
	return &netipAddr, nil
}
