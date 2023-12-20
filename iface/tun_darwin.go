//go:build !ios
// +build !ios

package iface

import (
	"os/exec"

	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	name    string
	address WGAddress
	mtu     int
	iceBind *bind.ICEBind

	device  *device.Device
	wrapper *DeviceWrapper
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) wgTunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
	}
}

func (c *tunDevice) Create() (wgConfigurer, error) {
	tunDevice, err := tun.CreateTUN(c.name, c.mtu)
	if err != nil {
		return nil, err
	}
	c.wrapper = newDeviceWrapper(tunDevice)

	// We need to create a wireguard-go device and listen to configuration requests
	c.device = device.NewDevice(
		c.wrapper,
		c.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)
	err = c.device.Up()
	if err != nil {
		c.device.Close()
		return nil, err
	}

	err = c.assignAddr()
	if err != nil {
		c.device.Close()
		return nil, err
	}

	log.Debugf("device is ready to use: %s", c.name)
	configurer := newWGUSPConfigurer(c.device)
	return configurer, nil
}

func (c *tunDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunDevice) Close() error {
	if c.device != nil {
		c.device.Close()
	}
	return nil
}

func (c *tunDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunDevice) DeviceName() string {
	return c.name
}

func (c *tunDevice) IceBind() *bind.ICEBind {
	return c.iceBind
}

func (c *tunDevice) Wrapper() *DeviceWrapper {
	return c.wrapper
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (c *tunDevice) assignAddr() error {
	cmd := exec.Command("ifconfig", c.name, "inet", c.address.IP.String(), c.address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof(`adding address command "%v" failed with output %s and error: `, cmd.String(), out)
		return err
	}

	routeCmd := exec.Command("route", "add", "-net", c.address.Network.String(), "-interface", c.name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		log.Printf(`adding route command "%v" failed with output %s and error: `, routeCmd.String(), out)
		return err
	}
	return nil
}
