//go:build ios
// +build ios

package device

import (
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
)

type TunDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	iceBind *bind.ICEBind
	tunFd   int

	device         *device.Device
	filteredDevice *FilteredDevice
	udpMux         *bind.UniversalUDPMuxDefault
	configurer     WGConfigurer
}

func NewTunDevice(name string, address WGAddress, port int, key string, iceBind *bind.ICEBind, tunFd int) *TunDevice {
	return &TunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		iceBind: iceBind,
		tunFd:   tunFd,
	}
}

func (t *TunDevice) Create() (WGConfigurer, error) {
	log.Infof("create tun interface")

	dupTunFd, err := unix.Dup(t.tunFd)
	if err != nil {
		log.Errorf("Unable to dup tun fd: %v", err)
		return nil, err
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		log.Errorf("Unable to set tun fd as non blocking: %v", err)
		_ = unix.Close(dupTunFd)
		return nil, err
	}
	tunDevice, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		log.Errorf("Unable to create new tun device from fd: %v", err)
		_ = unix.Close(dupTunFd)
		return nil, err
	}

	t.filteredDevice = newDeviceFilter(tunDevice)
	log.Debug("Attaching to interface")
	t.device = device.NewDevice(t.filteredDevice, t.iceBind, device.NewLogger(wgLogLevel(), "[wiretrustee] "))
	// without this property mobile devices can discover remote endpoints if the configured one was wrong.
	// this helps with support for the older NetBird clients that had a hardcoded direct mode
	// t.device.DisableSomeRoamingForBrokenMobileSemantics()

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name)
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.Close()
		return nil, err
	}
	return t.configurer, nil
}

func (t *TunDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
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

func (t *TunDevice) Device() *device.Device {
	return t.device
}

func (t *TunDevice) DeviceName() string {
	return t.name
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

func (t *TunDevice) WgAddress() WGAddress {
	return t.address
}

func (t *TunDevice) UpdateAddr(addr WGAddress) error {
	// todo implement
	return nil
}

func (t *TunDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}
