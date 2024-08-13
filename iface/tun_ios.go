//go:build ios
// +build ios

package iface

import (
	"fmt"
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	iceBind *bind.ICEBind
	tunFd   int

	device     *device.Device
	wrapper    *DeviceWrapper
	udpMux     *bind.UniversalUDPMuxDefault
	configurer wgConfigurer
}

func newTunDevice(name string, address WGAddress, port int, key string, transportNet transport.Net, tunFd int) *tunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		iceBind: bind.NewICEBind(transportNet),
		tunFd:   tunFd,
	}
}

func (t *tunDevice) Create() (wgConfigurer, error) {
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

	t.wrapper = newDeviceWrapper(tunDevice)
	log.Debug("Attaching to interface")
	t.device = device.NewDevice(t.wrapper, t.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	// without this property mobile devices can discover remote endpoints if the configured one was wrong.
	// this helps with support for the older NetBird clients that had a hardcoded direct mode
	// t.device.DisableSomeRoamingForBrokenMobileSemantics()

	t.configurer = newWGUSPConfigurer(t.device, t.name)
	err = t.configurer.configureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.close()
		return nil, err
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

func (t *tunDevice) Device() *device.Device {
	return t.device
}

func (t *tunDevice) DeviceName() string {
	return t.name
}

func (t *tunDevice) Close() error {
	if t.configurer != nil {
		t.configurer.close()
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

func (t *tunDevice) WgAddress6() *WGAddress {
	return nil
}

func (t *tunDevice) UpdateAddr(addr WGAddress) error {
	// todo implement
	return nil
}

func (t *tunDevice) UpdateAddr6(address6 *WGAddress) error {
	if address6 == nil {
		return nil
	}
	return fmt.Errorf("IPv6 is not supported on this operating system")
}

func (t *tunDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}
