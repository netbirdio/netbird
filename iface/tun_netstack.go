//go:build !android
// +build !android

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/netstack"
)

type tunNetstackDevice struct {
	name          string
	address       WGAddress
	port          int
	key           string
	mtu           int
	listenAddress string
	iceBind       *bind.ICEBind

	device     *device.Device
	wrapper    *DeviceWrapper
	nsTun      *netstack.NetStackTun
	udpMux     *bind.UniversalUDPMuxDefault
	configurer wgConfigurer
}

func newTunNetstackDevice(name string, address WGAddress, wgPort int, key string, mtu int, transportNet transport.Net, listenAddress string) wgTunDevice {
	return &tunNetstackDevice{
		name:          name,
		address:       address,
		port:          wgPort,
		key:           key,
		mtu:           mtu,
		listenAddress: listenAddress,
		iceBind:       bind.NewICEBind(transportNet),
	}
}

func (t *tunNetstackDevice) Create() (wgConfigurer, error) {
	log.Info("create netstack tun interface")
	t.nsTun = netstack.NewNetStackTun(t.listenAddress, t.address.IP.String(), t.mtu)
	tunIface, err := t.nsTun.Create()
	if err != nil {
		return nil, err
	}
	t.wrapper = newDeviceWrapper(tunIface)

	t.device = device.NewDevice(
		t.wrapper,
		t.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)

	t.configurer = newWGUSPConfigurer(t.device, t.name)
	err = t.configurer.configureInterface(t.key, t.port)
	if err != nil {
		_ = tunIface.Close()
		return nil, err
	}

	log.Debugf("device has been created: %s", t.name)
	return t.configurer, nil
}

func (t *tunNetstackDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
	if t.device == nil {
		return nil, fmt.Errorf("device is not ready yet")
	}

	err := t.device.Up()
	if err != nil {
		return nil, err
	}

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		return nil, err
	}
	t.udpMux = udpMux
	log.Debugf("netstack device is ready to use")
	return udpMux, nil
}

func (t *tunNetstackDevice) UpdateAddr(WGAddress) error {
	return nil
}

func (t *tunNetstackDevice) UpdateAddr6(address6 *WGAddress) error {
	if address6 == nil {
		return nil
	}
	return fmt.Errorf("IPv6 is not supported on this operating system")
}

func (t *tunNetstackDevice) Close() error {
	if t.configurer != nil {
		t.configurer.close()
	}

	if t.device != nil {
		t.device.Close()
	}

	if t.udpMux != nil {
		return t.udpMux.Close()
	}
	return nil
}

func (t *tunNetstackDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunNetstackDevice) WgAddress6() *WGAddress {
	return nil
}

func (t *tunNetstackDevice) DeviceName() string {
	return t.name
}

func (t *tunNetstackDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}
