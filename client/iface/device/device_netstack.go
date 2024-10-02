//go:build !android
// +build !android

package device

import (
	"fmt"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/netstack"
)

type tunNetstackDevice struct {
	name          string
	address       WGAddress
	port          int
	key           string
	mtu           int
	listenAddress string
	iceBind       *bind.ICEBind

	device         *device.Device
	filteredDevice *FilteredDevice
	nsTun          *netstack.NetStackTun
	udpMux         *bind.UniversalUDPMuxDefault
	configurer     WGConfigurer
}

func NewNetstackDevice(name string, address WGAddress, wgPort int, key string, mtu int, transportNet transport.Net, listenAddress string, filterFn bind.FilterFn) WGTunDevice {
	return &tunNetstackDevice{
		name:          name,
		address:       address,
		port:          wgPort,
		key:           key,
		mtu:           mtu,
		listenAddress: listenAddress,
		iceBind:       bind.NewICEBind(transportNet, filterFn),
	}
}

func (t *tunNetstackDevice) Create() (WGConfigurer, error) {
	log.Info("create netstack tun interface")
	t.nsTun = netstack.NewNetStackTun(t.listenAddress, t.address.IP.String(), t.mtu)
	tunIface, err := t.nsTun.Create()
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.filteredDevice = newDeviceFilter(tunIface)

	t.device = device.NewDevice(
		t.filteredDevice,
		t.iceBind,
		device.NewLogger(wgLogLevel(), "[netbird] "),
	)

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name)
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		_ = tunIface.Close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
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

func (t *tunNetstackDevice) Close() error {
	if t.configurer != nil {
		t.configurer.Close()
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

func (t *tunNetstackDevice) DeviceName() string {
	return t.name
}

func (t *tunNetstackDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}
