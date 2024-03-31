//go:build freebsd

package iface

import (
	"fmt"
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/freebsd"
)

type tunUSPDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	mtu     int
	iceBind *bind.ICEBind

	device     *device.Device
	wrapper    *DeviceWrapper
	udpMux     *bind.UniversalUDPMuxDefault
	configurer wgConfigurer
}

func newTunUSPDevice(name string, address WGAddress, port int, key string, mtu int, transportNet transport.Net) wgTunDevice {
	euid := os.Geteuid()
	if euid != 0 {
		log.Warn("tunUSPDevice: on freebsd netbird must run as root to be able to assign address to the tun interface with ifconfig")
	}

	return &tunUSPDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
	}
}

func (t *tunUSPDevice) Create() (wgConfigurer, error) {
	log.Info("create tun interface")

	tunIface, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		log.Debugf("failed to create tun unterface (%s, %d): %s", t.name, t.mtu, err)
		return nil, err
	}

	t.wrapper = newDeviceWrapper(tunIface)

	// We need to create a wireguard-go device and listen to configuration requests
	t.device = device.NewDevice(
		t.wrapper,
		t.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)

	err = t.assignAddr()
	if err != nil {
		t.device.Close()

		return nil, err
	}

	t.configurer = newWGUSPConfigurer(t.device, t.name)

	err = t.configurer.configureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.close()

		return nil, err
	}

	return t.configurer, nil
}

func (t *tunUSPDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
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

func (t *tunUSPDevice) UpdateAddr(address WGAddress) error {
	t.address = address

	return t.assignAddr()
}

func (t *tunUSPDevice) Close() error {
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

func (t *tunUSPDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunUSPDevice) DeviceName() string {
	return t.name
}

func (t *tunUSPDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}

// assignAddr Adds IP address to the tunnel interface
func (t *tunUSPDevice) assignAddr() error {
	link, err := freebsd.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}

	ip := t.address.IP.String()
	mask := "0x" + t.address.Network.Mask.String()

	log.Infof("assign addr %s mask %s to %s interface", ip, mask, t.name)

	err = link.AssignAddr(ip, mask)
	if err != nil {
		return fmt.Errorf("assign addr: %w", err)
	}

	err = link.Up()
	if err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}
