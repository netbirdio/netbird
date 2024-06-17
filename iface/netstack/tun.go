package netstack

import (
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type NetStackTun struct { //nolint:revive
	address       string
	mtu           int
	listenAddress string

	proxy  *Proxy
	tundev tun.Device
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
	t.tundev = nsTunDev

	dialer := NewNSDialer(tunNet)
	t.proxy, err = NewSocks5(dialer)
	if err != nil {
		_ = t.tundev.Close()
		return nil, err
	}

	go func() {
		err := t.proxy.ListenAndServe(t.listenAddress)
		if err != nil {
			log.Errorf("error in socks5 proxy serving: %s", err)
		}
	}()

	return nsTunDev, nil
}

func (t *NetStackTun) Close() error {
	var err error
	if t.proxy != nil {
		pErr := t.proxy.Close()
		if pErr != nil {
			log.Errorf("failed to close socks5 proxy: %s", pErr)
			err = pErr
		}
	}

	if t.tundev != nil {
		dErr := t.tundev.Close()
		if dErr != nil {
			log.Errorf("failed to close netstack tun device: %s", dErr)
			err = dErr
		}
	}

	return err
}
