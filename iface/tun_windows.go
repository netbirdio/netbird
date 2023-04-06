package iface

import (
	"fmt"
	"github.com/netbirdio/netbird/iface/bind"
	"github.com/pion/transport/v2"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
)

type tunDevice struct {
	name         string
	address      WGAddress
	netInterface NetInterface
	iceBind      *bind.ICEBind
}

func newTunDevice(name string, address WGAddress, mtu int, transportNet transport.Net) *tunDevice {
	return &tunDevice{name: name, address: address, iceBind: bind.NewICEBind(transportNet)}
}

func (c *tunDevice) Create() error {
	var err error
	c.netInterface, err = c.createWithUserspace()
	if err != nil {
		return err
	}

	return c.assignAddr()
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

	return c.netInterface.Close()
}

func (c *tunDevice) getInterfaceGUIDString() (string, error) {
	if c.netInterface == nil {
		return "", fmt.Errorf("interface has not been initialized yet")
	}
	windowsDevice := c.netInterface.(*driver.Adapter)
	luid := windowsDevice.LUID()
	guid, err := luid.GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

func (c *tunDevice) createAdapter() (NetInterface, error) {
	WintunStaticRequestedGUID, _ := windows.GenerateGUID()
	adapter, err := driver.CreateAdapter(c.name, "WireGuard", &WintunStaticRequestedGUID)
	if err != nil {
		err = fmt.Errorf("error creating adapter: %w", err)
		return nil, err
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return adapter, err
	}
	state, _ := adapter.LUID().GUID()
	log.Debugln("device guid: ", state.String())
	return adapter, nil
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (c *tunDevice) assignAddr() error {
	luid := c.netInterface.(*driver.Adapter).LUID()

	log.Debugf("adding address %s to interface: %s", c.address.IP, c.name)
	err := luid.SetIPAddresses([]net.IPNet{{c.address.IP, c.address.Network.Mask}})
	if err != nil {
		return err
	}

	return nil
}
