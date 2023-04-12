//go:build (linux || darwin) && !android

package iface

import (
	"github.com/netbirdio/netbird/iface/bind"
	"github.com/pion/transport/v2"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDevice struct {
	name         string
	address      WGAddress
	mtu          int
	netInterface NetInterface
	iceBind      *bind.ICEBind
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) *tunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
	}
}

func (c *tunDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunDevice) DeviceName() string {
	return c.name
}

func (c *tunDevice) Close() error {
	if c.netInterface == nil {
		return nil
	}
	err := c.netInterface.Close()
	if err != nil {
		return err
	}

	sockPath := "/var/run/wireguard/" + c.name + ".sock"
	if _, statErr := os.Stat(sockPath); statErr == nil {
		statErr = os.Remove(sockPath)
		if statErr != nil {
			return statErr
		}
	}

	return nil
}

// createWithUserspace Creates a new Wireguard interface, using wireguard-go userspace implementation
func (c *tunDevice) createWithUserspace() (NetInterface, error) {
	tunIface, err := tun.CreateTUN(c.name, c.mtu)
	if err != nil {
		return nil, err
	}

	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, c.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return tunIface, err
	}

	log.Debugln("UAPI listener started")
	return tunIface, nil
}
