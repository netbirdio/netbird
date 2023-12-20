//go:build android
// +build android

package iface

import (
	"strings"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

// ignore the wgTunDevice interface on Android because the creation of the tun device is different on this platform
type wgTunDevice struct {
	address    WGAddress
	mtu        int
	iceBind    *bind.ICEBind
	tunAdapter TunAdapter

	name    string
	device  *device.Device
	wrapper *DeviceWrapper
}

func newTunDevice(address WGAddress, mtu int, transportNet transport.Net, tunAdapter TunAdapter) wgTunDevice {
	return wgTunDevice{
		address:    address,
		mtu:        mtu,
		iceBind:    bind.NewICEBind(transportNet),
		tunAdapter: tunAdapter,
	}
}

func (t *wgTunDevice) Create(routes []string, dns string, searchDomains []string) (wgConfigurer, error) {
	log.Info("create tun interface")

	routesString := routesToString(routes)
	searchDomainsToString := searchDomainsToString(searchDomains)

	fd, err := t.tunAdapter.ConfigureInterface(t.address.String(), t.mtu, dns, searchDomainsToString, routesString)
	if err != nil {
		log.Errorf("failed to create Android interface: %s", err)
		return nil, err
	}

	tunDevice, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		_ = unix.Close(fd)
		log.Errorf("failed to create Android interface: %s", err)
		return nil, err
	}
	t.name = name
	t.wrapper = newDeviceWrapper(tunDevice)

	log.Debugf("attaching to interface %v", name)
	t.device = device.NewDevice(t.wrapper, t.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	// without this property mobile devices can discover remote endpoints if the configured one was wrong.
	// this helps with support for the older NetBird clients that had a hardcoded direct mode
	// t.device.DisableSomeRoamingForBrokenMobileSemantics()

	err = t.device.Up()
	if err != nil {
		t.device.Close()
		return nil, err
	}

	configurer := newWGUSPConfigurer(t.device)

	log.Debugf("device is ready to use: %s", name)
	return configurer, nil
}

func (t *wgTunDevice) UpdateAddr(addr WGAddress) error {
	// todo implement
	return nil
}

func (t *wgTunDevice) Close() (err error) {
	if t.device != nil {
		t.device.Close()
	}
	return
}

func (t *wgTunDevice) Device() *device.Device {
	return t.device
}

func (t *wgTunDevice) DeviceName() string {
	return t.name
}

func (t *wgTunDevice) WgAddress() WGAddress {
	return t.address
}

func (t *wgTunDevice) IceBind() *bind.ICEBind {
	return t.iceBind
}

func (t *wgTunDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}

func routesToString(routes []string) string {
	return strings.Join(routes, ";")
}

func searchDomainsToString(searchDomains []string) string {
	return strings.Join(searchDomains, ";")
}
