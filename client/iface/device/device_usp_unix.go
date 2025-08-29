//go:build (linux && !android) || freebsd

package device

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type USPDevice struct {
	name    string
	address wgaddr.Address
	port    int
	key     string
	mtu     int
	iceBind *bind.ICEBind

	device         *device.Device
	filteredDevice *FilteredDevice
	udpMux         *bind.UniversalUDPMuxDefault
	configurer     WGConfigurer
}

func NewUSPDevice(name string, address wgaddr.Address, port int, key string, mtu int, iceBind *bind.ICEBind) *USPDevice {
	log.Infof("using userspace bind mode")

	return &USPDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: iceBind,
	}
}

func (t *USPDevice) Create() (WGConfigurer, error) {
	log.Info("create tun interface")
	tunIface, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		log.Debugf("failed to create tun interface (%s, %d): %s", t.name, t.mtu, err)
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.filteredDevice = newDeviceFilter(tunIface)

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

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name, t.iceBind.ActivityRecorder())
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.Close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}
	return t.configurer, nil
}

func (t *USPDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
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

	log.Debugf("device is ready to use: %s", t.name)
	return udpMux, nil
}

func (t *USPDevice) UpdateAddr(address wgaddr.Address) error {
	t.address = address
	return t.assignAddr()
}

func (t *USPDevice) Close() error {
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

func (t *USPDevice) WgAddress() wgaddr.Address {
	return t.address
}

func (t *USPDevice) DeviceName() string {
	return t.name
}

func (t *USPDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}

// Device returns the wireguard device
func (t *USPDevice) Device() *device.Device {
	return t.device
}

// assignAddr Adds IP address to the tunnel interface
func (t *USPDevice) assignAddr() error {
	link := newWGLink(t.name)

	return link.assignAddr(t.address)
}

func (t *USPDevice) GetNet() *netstack.Net {
	return nil
}
