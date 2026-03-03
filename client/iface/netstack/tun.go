package netstack

import (
	"net/netip"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const EnvSkipProxy = "NB_NETSTACK_SKIP_PROXY"

type NetStackTun struct { //nolint:revive
	address       netip.Addr
	dnsAddress    netip.Addr
	mtu           int
	listenAddress string

	proxy  *Proxy
	tundev tun.Device
}

func NewNetStackTun(listenAddress string, address netip.Addr, dnsAddress netip.Addr, mtu int) *NetStackTun {
	return &NetStackTun{
		address:       address,
		dnsAddress:    dnsAddress,
		mtu:           mtu,
		listenAddress: listenAddress,
	}
}

func (t *NetStackTun) Create() (tun.Device, *netstack.Net, error) {
	nsTunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{t.address},
		[]netip.Addr{t.dnsAddress},
		t.mtu)
	if err != nil {
		return nil, nil, err
	}
	t.tundev = nsTunDev

	var skipProxy bool
	if val := os.Getenv(EnvSkipProxy); val != "" {
		skipProxy, err = strconv.ParseBool(val)
		if err != nil {
			log.Errorf("failed to parse %s: %s", EnvSkipProxy, err)
		}
	}
	if skipProxy {
		return nsTunDev, tunNet, nil
	}

	dialer := NewNSDialer(tunNet)
	t.proxy, err = NewSocks5(dialer)
	if err != nil {
		_ = t.tundev.Close()
		return nil, nil, err
	}

	go func() {
		err := t.proxy.ListenAndServe(t.listenAddress)
		if err != nil {
			log.Errorf("error in socks5 proxy serving: %s", err)
		}
	}()

	return t.tundev, tunNet, nil
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
