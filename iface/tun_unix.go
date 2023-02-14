//go:build (linux || darwin) && !android

package iface

import (
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDevice struct {
	name         string
	address      WGAddress
	mtu          int
	netInterface NetInterface
}

func newTunDevice(name string, address WGAddress, mtu int) tunDevice {
	return tunDevice{
		name:    name,
		address: address,
		mtu:     mtu,
	}
}

func (c *tunDevice) updateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunDevice) wgAddress() WGAddress {
	return c.address
}

func (t *tunDevice) deviceName() string {
	return t.name
}

func (c *tunDevice) close() error {
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
	tunDevice := device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return tunIface, err
	}
	uapi, err := c.getUAPI(c.name)
	if err != nil {
		return tunIface, err
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

// getUAPI returns a Listener
func (c *tunDevice) getUAPI(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
