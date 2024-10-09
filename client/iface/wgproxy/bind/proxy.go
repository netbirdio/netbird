package bind

import (
	"context"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bind"
)

type ProxyBind struct {
	Bind *bind.ICEBind

	wgAddr     *net.UDPAddr
	wgEndpoint *bind.Endpoint
	remoteConn net.Conn
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

	go p.proxyToLocal(ctx)
	return err

}
func (p *ProxyBind) EndpointAddr() *net.UDPAddr {
	return p.wgAddr
}

func (p *ProxyBind) Work() {
	// todo implement me
}

func (p *ProxyBind) Pause() {
	// todo implement me
}

func (p *ProxyBind) CloseConn() error {
	p.Bind.RemoveEndpoint(p.wgAddr)
	return nil
}

func (p *ProxyBind) proxyToLocal(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		n, err := p.remoteConn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("failed to read from remote conn: %s, %s", p.remoteConn.RemoteAddr(), err)
			return
		}

		msg := bind.RecvMessage{
			Endpoint: p.wgEndpoint,
			Buffer:   buf,
			Len:      n,
		}
		p.Bind.RecvChan <- msg
	}
}

func addrToEndpoint(addr *net.UDPAddr) *bind.Endpoint {
	ip, _ := netip.AddrFromSlice(addr.IP.To4())
	addrPort := netip.AddrPortFrom(ip, uint16(addr.Port))
	return &bind.Endpoint{AddrPort: addrPort}
}
