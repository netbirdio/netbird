//go:build (linux || darwin) && !android

package iface

import (
	"net"
	"os"

	"github.com/pion/transport/v2"
	"golang.zx2c4.com/wireguard/ipc"

	"github.com/netbirdio/netbird/iface/bind"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDevice struct {
	name         string
	address      WGAddress
	address6     *WGAddress
	mtu          int
	netInterface NetInterface
	iceBind      *bind.ICEBind
	uapi         net.Listener
	wrapper      *DeviceWrapper
	close        chan struct{}
}

func newTunDevice(name string, address WGAddress, address6 *WGAddress, mtu int, transportNet transport.Net) *tunDevice {
	return &tunDevice{
		name:     name,
		address:  address,
		address6: address6,
		mtu:      mtu,
		iceBind:  bind.NewICEBind(transportNet),
		close:    make(chan struct{}),
	}
}

func (c *tunDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunDevice) UpdateAddr6(address6 *WGAddress) error {
	c.address6 = address6
	return c.assignAddr()
}

func (c *tunDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunDevice) WgAddress6() *WGAddress {
	return c.address6
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
	tunIface, err := tun.CreateTUN(c.name, c.mtu)
	if err != nil {
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
		_ = tunIface.Close()
		return nil, err
	}

	c.uapi, err = c.getUAPI(c.name)
	if err != nil {
		_ = tunIface.Close()
		return nil, err
	}

	go func() {
		for {
			select {
			case <-c.close:
				log.Debugf("exit uapi.Accept()")
				return
			default:
			}
			uapiConn, uapiErr := c.uapi.Accept()
			if uapiErr != nil {
				log.Traceln("uapi Accept failed with error: ", uapiErr)
				continue
			}
			go func() {
				tunDev.IpcHandle(uapiConn)
				log.Debugf("exit tunDevice.IpcHandle")
			}()
		}
	}()

	log.Debugln("UAPI listener started")
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
