package bind

import (
	"context"
	"net"

	"github.com/netbirdio/netbird/client/iface/bind"
)

type ProxyBind struct {
	Bind *bind.ICEBind

	addr *net.UDPAddr
}

func (p *ProxyBind) AddTurnConn(_ context.Context, endpoint *net.UDPAddr, relayedConn net.Conn) error {
	addr, err := p.Bind.SetEndpoint(endpoint, relayedConn)
	if err != nil {
		return err
	}

	p.addr = addr
	return err

}

func (p *ProxyBind) EndpointAddr() *net.UDPAddr {
	return p.addr
}

func (p *ProxyBind) Work() {
	// todo implement me
}

func (p *ProxyBind) Pause() {
	// todo implement me
}

func (p *ProxyBind) CloseConn() error {
	p.Bind.RemoveEndpoint(p.addr)
	return nil
}
