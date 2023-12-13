package uspproxy

import (
	"context"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type NSDialer struct {
	net *netstack.Net
}

func (d *NSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.net.Dial(network, addr)
	if err != nil {
		log.Debugf("failed to deal connection: %s", err)
	}
	return conn, err
}

type NetStackTun struct {
	address string

	proxy *Proxy
}

func NewNetStackTun(address string) *NetStackTun {
	return &NetStackTun{
		address: address,
	}
}

func (t *NetStackTun) Create() (tun.Device, error) {
	nsTunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(t.address)},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1420)
	if err != nil {
		return nil, err
	}

	dialer := &NSDialer{tunNet}
	t.proxy, err = NewSocks5(dialer)
	if err != nil {
		// close nsTunDev
		return nil, err
	}

	err = t.proxy.ListenAndServe("127.0.0.1:1234")
	return nsTunDev, nil
}
