package netstack

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type NetStackTun struct {
	address       string
	mtu           int
	listenAddress string

	proxy *Proxy
}

func NewNetStackTun(listenAddress string, address string, mtu int) *NetStackTun {
	return &NetStackTun{
		address:       address,
		mtu:           mtu,
		listenAddress: listenAddress,
	}
}

func (t *NetStackTun) Create() (tun.Device, error) {
	nsTunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(t.address)},
		[]netip.Addr{},
		t.mtu)
	if err != nil {
		return nil, err
	}

	dialer := NewNSDialer(tunNet)
	t.proxy, err = NewSocks5(dialer)
	if err != nil {
		// todo close nsTunDev
		return nil, err
	}

	t.proxy.ListenAndServe(t.listenAddress)
	return nsTunDev, nil
}
