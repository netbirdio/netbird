//go:build linux && !android

package iface

import (
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunUSPDevice struct {
	name    string
	address WGAddress
	mtu     int
	iceBind *bind.ICEBind

	device  *device.Device
	wrapper *DeviceWrapper
}

func newTunUSPDevice(name string, address WGAddress, mtu int, transportNet transport.Net) wgTunDevice {
	return &tunUSPDevice{
		name:    name,
		address: address,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
	}
}

func (c *tunUSPDevice) Create() (wgConfigurer, error) {
	log.Info("create tun interface")
	tunIface, err := tun.CreateTUN(c.name, c.mtu)
	if err != nil {
		return nil, err
	}
	c.wrapper = newDeviceWrapper(tunIface)

	// We need to create a wireguard-go device and listen to configuration requests
	c.device = device.NewDevice(
		c.wrapper,
		c.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)
	err = c.device.Up()
	if err != nil {
		_ = tunIface.Close()
		return nil, err
	}

	err = c.assignAddr()
	if err != nil {
		c.device.Close()
		return nil, err
	}

	configurer := newWGUSPConfigurer(c.device)

	log.Debugf("device is ready to use: %s", c.name)
	return configurer, nil
}

func (c *tunUSPDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunUSPDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunUSPDevice) DeviceName() string {
	return c.name
}

func (c *tunUSPDevice) IceBind() *bind.ICEBind {
	return c.iceBind
}

func (c *tunUSPDevice) Wrapper() *DeviceWrapper {
	return c.wrapper
}

func (c *tunUSPDevice) Close() error {
	if c.device != nil {
		c.device.Close()
	}
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (c *tunUSPDevice) assignAddr() error {
	link := newWGLink(c.name)

	//delete existing addresses
	list, err := netlink.AddrList(link, 0)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		for _, a := range list {
			addr := a
			err = netlink.AddrDel(link, &addr)
			if err != nil {
				return err
			}
		}
	}

	log.Debugf("adding address %s to interface: %s", c.address.String(), c.name)
	addr, _ := netlink.ParseAddr(c.address.String())
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", c.name, c.address.String())
	} else if err != nil {
		return err
	}
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}
