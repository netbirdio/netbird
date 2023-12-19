package iface

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	name    string
	address WGAddress
	mtu     int
	iceBind *bind.ICEBind

	device          *device.Device
	nativeTunDevice *tun.NativeTun
	wrapper         *DeviceWrapper
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) *tunDevice {
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
	c.nativeTunDevice = tunDevice.(*tun.NativeTun)
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

	luid := winipcfg.LUID(c.nativeTunDevice.LUID())

	nbiface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		c.device.Close()
		return nil, fmt.Errorf("got error when getting ip interface %s", err)
	}

	nbiface.NLMTU = uint32(c.mtu)

	err = nbiface.Set()
	if err != nil {
		c.device.Close()
		return nil, fmt.Errorf("got error when getting setting the interface mtu: %s", err)
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

func (c *tunDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunDevice) DeviceName() string {
	return c.name
}

func (c *tunDevice) Close() error {
	if c.device != nil {
		c.device.Close()
	}
	return nil
}

func (c *tunDevice) getInterfaceGUIDString() (string, error) {
	if c.nativeTunDevice == nil {
		return "", fmt.Errorf("interface has not been initialized yet")
	}

	luid := winipcfg.LUID(c.nativeTunDevice.LUID())
	guid, err := luid.GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (c *tunDevice) assignAddr() error {
	luid := winipcfg.LUID(c.nativeTunDevice.LUID())
	log.Debugf("adding address %s to interface: %s", c.address.IP, c.name)
	return luid.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix(c.address.String())})
}

// getUAPI returns a Listener
func (c *tunDevice) getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}
