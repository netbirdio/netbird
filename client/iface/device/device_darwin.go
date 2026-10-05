//go:build !ios

package device

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type TunDevice struct {
	name    string
	address wgaddr.Address
	port    int
	key     string
	mtu     uint16
	iceBind *bind.ICEBind

	device         *device.Device
	filteredDevice *FilteredDevice
	udpMux         *udpmux.UniversalUDPMuxDefault
	configurer     WGConfigurer
}

func NewTunDevice(name string, address wgaddr.Address, port int, key string, mtu uint16, iceBind *bind.ICEBind) *TunDevice {
	return &TunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: iceBind,
	}
}

func (t *TunDevice) Create() (WGConfigurer, error) {
	tunDevice, err := tun.CreateTUN(t.name, int(t.mtu))
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

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name, t.iceBind.ActivityRecorder())
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.Close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}
	return t.configurer, nil
}

func (t *TunDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
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

func (t *TunDevice) UpdateAddr(address wgaddr.Address) error {
	t.address = address
	return t.assignAddr()
}

func (t *TunDevice) Close() error {
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

func (t *TunDevice) WgAddress() wgaddr.Address {
	return t.address
}

func (t *TunDevice) MTU() uint16 {
	return t.mtu
}

func (t *TunDevice) DeviceName() string {
	return t.name
}

func (t *TunDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}

// Device returns the wireguard device
func (t *TunDevice) Device() *device.Device {
	return t.device
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (t *TunDevice) assignAddr() error {
	if out, err := exec.Command("ifconfig", t.name, "inet", t.address.IP.String(), t.address.IP.String()).CombinedOutput(); err != nil {
		return fmt.Errorf("add v4 address: %s: %w", string(out), err)
	}

	// Assign a dummy link-local so macOS enables IPv6 on the tun device.
	// When a real overlay v6 is present, use that instead.
	v6Addr := "fe80::/64"
	if t.address.HasIPv6() {
		v6Addr = t.address.IPv6String()
	}
	if out, err := exec.Command("ifconfig", t.name, "inet6", v6Addr).CombinedOutput(); err != nil {
		log.Warnf("failed to assign IPv6 address %s, continuing v4-only: %s: %v", v6Addr, string(out), err)
		t.address.ClearIPv6()
	}

	if out, err := exec.Command("route", "add", "-net", t.address.Network.String(), "-interface", t.name).CombinedOutput(); err != nil {
		return fmt.Errorf("add route %s via %s: %s: %w", t.address.Network, t.name, string(out), err)
	}

	if t.address.HasIPv6() {
		if out, err := exec.Command("route", "add", "-inet6", "-net", t.address.IPv6Net.String(), "-interface", t.name).CombinedOutput(); err != nil {
			log.Warnf("failed to add route %s via %s, continuing v4-only: %s: %v", t.address.IPv6Net, t.name, string(out), err)
			t.address.ClearIPv6()
		}
	}

	return nil
}

func (t *TunDevice) GetNet() *netstack.Net {
	return nil
}

// GetICEBind returns the ICEBind instance
func (t *TunDevice) GetICEBind() EndpointManager {
	return t.iceBind
}
