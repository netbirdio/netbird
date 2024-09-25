//go:build !ios

package device

import (
	"fmt"
	"os/exec"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/configurer"
)

type tunDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	mtu     int
	iceBind *bind.ICEBind

	device         *device.Device
	filteredDevice *FilteredDevice
	udpMux         *bind.UniversalUDPMuxDefault
	configurer     configurer.WGConfigurer
}

func NewTunDevice(name string, address WGAddress, port int, key string, mtu int, transportNet transport.Net, filterFn bind.FilterFn) WGTunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet, filterFn),
	}
}

func (t *tunDevice) Create() (configurer.WGConfigurer, error) {
	tunDevice, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.filteredDevice = newDeviceFilter(tunDevice)

	// We need to create a wireguard-go device and listen to configuration requests
	t.device = device.NewDevice(
		t.filteredDevice,
		t.iceBind,
		device.NewLogger(wgLogLevel(), "[netbird] "),
	)

	err = t.assignAddr()
	if err != nil {
		t.device.Close()
		return nil, fmt.Errorf("error assigning ip: %s", err)
	}

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name)
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.Close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}
	return t.configurer, nil
}

func (t *tunDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
	err := t.device.Up()
	if err != nil {
		return nil, err
	}

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		return nil, err
	}
	t.udpMux = udpMux
	log.Debugf("device is ready to use: %s", t.name)
	return udpMux, nil
}

func (t *tunDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunDevice) Close() error {
	if t.configurer != nil {
		t.configurer.Close()
	}

	if t.device != nil {
		t.device.Close()
		t.device = nil
	}

	if t.udpMux != nil {
		return t.udpMux.Close()
	}
	return nil
}

func (t *tunDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunDevice) DeviceName() string {
	return t.name
}

func (t *tunDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (t *tunDevice) assignAddr() error {
	cmd := exec.Command("ifconfig", t.name, "inet", t.address.IP.String(), t.address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("adding address command '%v' failed with output: %s", cmd.String(), out)
		return err
	}

	// dummy ipv6 so routing works
	cmd = exec.Command("ifconfig", t.name, "inet6", "fe80::/64")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Debugf("adding address command '%v' failed with output: %s", cmd.String(), out)
	}

	routeCmd := exec.Command("route", "add", "-net", t.address.Network.String(), "-interface", t.name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		log.Errorf("adding route command '%v' failed with output: %s", routeCmd.String(), out)
		return err
	}
	return nil
}
