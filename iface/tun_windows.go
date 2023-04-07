package iface

import (
	"fmt"
	"github.com/netbirdio/netbird/iface/bind"
	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
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
	tunDevice := device.NewDevice(tunIface, c.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return tunIface, err
	}

	uapi, err := c.getUAPI(c.name)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			uapiConn, uapiErr := uapi.Accept()
			if uapiErr != nil {
				log.Traceln("uapi Accept failed with error: ", uapiErr)
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
	tunDev := c.netInterface.(*tun.NativeTun)
	luid := winipcfg.LUID(tunDev.LUID())
	log.Debugf("adding address %s to interface: %s", c.address.IP, c.name)
	return luid.SetIPAddresses([]net.IPNet{{c.address.IP, c.address.Network.Mask}})
}

// getUAPI returns a Listener
func (c *tunDevice) getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}
