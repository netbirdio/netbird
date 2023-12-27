//go:build !android
// +build !android

package iface

import (
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/netstack"
)

type tunNetstackDevice struct {
	name          string
	address       WGAddress
	mtu           int
	listenAddress string
	iceBind       *bind.ICEBind

	device  *device.Device
	wrapper *DeviceWrapper
	nsTun   *netstack.NetStackTun
	udpMux  *bind.UniversalUDPMuxDefault
}

func newTunNetstackDevice(name string, address WGAddress, mtu int, transportNet transport.Net, listenAddress string) wgTunDevice {
	return &tunNetstackDevice{
		name:          name,
		address:       address,
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

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		_ = tunIface.Close()
		return nil, err
	}
	t.udpMux = udpMux

	configurer := newWGUSPConfigurer(t.device)

	log.Debugf("device is ready to use: %s", t.name)
	return configurer, nil
}

func (t *tunNetstackDevice) UpdateAddr(WGAddress) error {
	return nil
}

func (t *tunNetstackDevice) Close() error {
	if t.device == nil {
		return nil
	}

	t.device.Close()
	return t.udpMux.Close()
}

func (t *tunNetstackDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunNetstackDevice) DeviceName() string {
	return t.name
}

func (t *tunNetstackDevice) IceBind() *bind.ICEBind {
	return t.iceBind
}

func (t *tunNetstackDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}

func (t *tunNetstackDevice) UdpMux() *bind.UniversalUDPMuxDefault {
	return t.udpMux
}
