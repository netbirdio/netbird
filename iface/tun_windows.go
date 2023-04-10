package iface

import (
	"fmt"
	"github.com/netbirdio/netbird/iface/bind"
	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
)

type tunDevice struct {
	name         string
	address      WGAddress
	netInterface NetInterface
	uapi         net.Listener
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

	uapi, err := c.getUAPI(c.name)
	if err != nil {
		return nil, err
	}
	c.uapi = uapi

	go func() {
		for {
			uapiConn, uapiErr := uapi.Accept()
			if uapiErr != nil {
				log.Traceln("uapi accept failed with error: ", uapiErr)
				continue
			}
			go tunDevice.IpcHandle(uapiConn)
		}
	}()

	log.Debugln("UAPI listener started")
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
	var err1, err2 error
	if c.netInterface == nil {
		err1 = c.netInterface.Close()
	}

	if c.uapi != nil {
		err2 = c.uapi.Close()
	}

	if err1 != nil {
		return err1
	}

	return err2
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

// getUAPI returns a Listener
func (c *tunDevice) getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}
