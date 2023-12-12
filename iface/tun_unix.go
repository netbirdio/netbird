//go:build (linux || darwin) && !android

package iface

import (
	"net"
	"net/netip"
	"os"

	"github.com/pion/transport/v2"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/iface/bind"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
)

type tunDevice struct {
	name         string
	address      WGAddress
	mtu          int
	netInterface NetInterface
	iceBind      *bind.ICEBind
	uapi         net.Listener
	wrapper      *DeviceWrapper
	close        chan struct{}
	tunDevice    *device.Device
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) *tunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
		close:   make(chan struct{}),
	}
}

func (c *tunDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunDevice) WgAddress() WGAddress {
	return c.address
}

func (t *tunDevice) Device() *device.Device {
	return t.tunDevice
}

func (c *tunDevice) DeviceName() string {
	return c.name
}

func (c *tunDevice) Close() error {

	select {
	case c.close <- struct{}{}:
	default:
	}

	var err1, err2, err3 error
	if c.netInterface != nil {
		err1 = c.netInterface.Close()
	}

	if c.uapi != nil {
		err2 = c.uapi.Close()
	}

	sockPath := "/var/run/wireguard/" + c.name + ".sock"
	if _, statErr := os.Stat(sockPath); statErr == nil {
		statErr = os.Remove(sockPath)
		if statErr != nil {
			err3 = statErr
		}
	}

	if err1 != nil {
		return err1
	}

	if err2 != nil {
		return err2
	}

	return err3
}

// createWithUserspace Creates a new Wireguard interface, using wireguard-go userspace implementation
func (c *tunDevice) createWithUserspace() (NetInterface, error) {
	tunIface, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(c.address.IP.String())},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1420)
	if err != nil {
		log.Debugf("createWithUserspace failed with error: %v", err)
		return nil, err
	}
	c.wrapper = newDeviceWrapper(tunIface)

	// We need to create a wireguard-go device and listen to configuration requests
	tunDev := device.NewDevice(
		c.wrapper,
		c.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)
	err = tunDev.Up()
	if err != nil {
		log.Debugf("tunDev.Up() failed with error: %v", err)
		_ = tunIface.Close()
		return nil, err
	}

	c.tunDevice = tunDev
	return tunIface, nil
}

// getUAPI returns a Listener
func (c *tunDevice) getUAPI(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
