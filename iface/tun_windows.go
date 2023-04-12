package iface

import (
	"fmt"
	"net"

	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	name         string
	address      WGAddress
	netInterface NetInterface
	iceBind      *bind.ICEBind
	mtu          int
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) *tunDevice {
	return &tunDevice{name: name, address: address, iceBind: bind.NewICEBind(transportNet), mtu: mtu}
}

func (c *tunDevice) Create() error {
	var err error
	c.netInterface, err = c.createWithUserspace()
	if err != nil {
		return err
	}

	return c.assignAddr()
}

// createWithUserspace Creates a new WireGuard interface, using wireguard-go userspace implementation
func (c *tunDevice) createWithUserspace() (NetInterface, error) {

	tunIface, err := tun.CreateTUN(c.name, c.mtu)
	if err != nil {
		return nil, err
	}
	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, c.iceBind, device.NewLogger(device.LogLevelSilent, "[netbird] "))
	err = tunDevice.Up()
	if err != nil {
		return tunIface, err
	}
	return tunIface, nil
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
	if c.netInterface != nil {
		return c.netInterface.Close()
	}
	return nil
}

func (c *tunDevice) getInterfaceGUIDString() (string, error) {
	if c.netInterface == nil {
		return "", fmt.Errorf("interface has not been initialized yet")
	}
	windowsDevice := c.netInterface.(*tun.NativeTun)
	luid := winipcfg.LUID(windowsDevice.LUID())
	guid, err := luid.GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (c *tunDevice) assignAddr() error {
	tunDev := c.netInterface.(*tun.NativeTun)
	luid := winipcfg.LUID(tunDev.LUID())
	log.Debugf("adding address %s to interface: %s", c.address.IP, c.name)
	return luid.SetIPAddresses([]net.IPNet{{c.address.IP, c.address.Network.Mask}})
}
