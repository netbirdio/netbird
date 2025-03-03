package netstack

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const EnvSkipProxy = "NB_NETSTACK_SKIP_PROXY"

type NetStackTun struct { //nolint:revive
	address       net.IP
	dnsAddress    net.IP
	mtu           int
	listenAddress string

	proxy  *Proxy
	tundev tun.Device
}

func NewNetStackTun(listenAddress string, address net.IP, dnsAddress net.IP, mtu int) *NetStackTun {
	return &NetStackTun{
		address:       address,
		dnsAddress:    dnsAddress,
		mtu:           mtu,
		listenAddress: listenAddress,
	}
}

func (t *NetStackTun) Create() (tun.Device, *netstack.Net, error) {
	addr, ok := netip.AddrFromSlice(t.address)
	if !ok {
		return nil, nil, fmt.Errorf("convert address to netip.Addr: %v", t.address)
	}

	dnsAddr, ok := netip.AddrFromSlice(t.dnsAddress)
	if !ok {
		return nil, nil, fmt.Errorf("convert dns address to netip.Addr: %v", t.dnsAddress)
	}

	nsTunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{addr.Unmap()},
		[]netip.Addr{dnsAddr.Unmap()},
		t.mtu)
	if err != nil {
		return nil, nil, err
	}
	t.tundev = nsTunDev

	skipProxy, err := strconv.ParseBool(os.Getenv(EnvSkipProxy))
	if err != nil {
		log.Errorf("failed to parse %s: %s", EnvSkipProxy, err)
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

	return nsTunDev, tunNet, nil
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
