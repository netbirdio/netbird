package iface

import (
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDevice struct {
	address   WGAddress
	mtu       int
	wgAdapter WGAdapter

	fd     int
	name   string
	device *device.Device
	uapi   net.Listener
}

func newTunDevice(address WGAddress, mtu int, wgAdapter WGAdapter) *tunDevice {
	return &tunDevice{
		address:   address,
		mtu:       mtu,
		wgAdapter: wgAdapter,
	}
}

func (t *tunDevice) Create() error {
	var err error
	t.fd, err = t.wgAdapter.ConfigureInterface(t.address.String(), t.mtu)
	if err != nil {
		log.Errorf("failed to create Android interface: %s", err)
		return err
	}

	tunDevice, name, err := tun.CreateUnmonitoredTUNFromFD(t.fd)
	if err != nil {
		unix.Close(t.fd)
		return err
	}
	t.name = name

	log.Debugf("attaching to interface %v", name)
	t.device = device.NewDevice(tunDevice, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	t.device.DisableSomeRoamingForBrokenMobileSemantics()

	log.Debugf("create uapi")
	tunSock, err := ipc.UAPIOpen(name)
	if err != nil {
		return err
	}

	t.uapi, err = ipc.UAPIListen(name, tunSock)
	if err != nil {
		tunSock.Close()
		unix.Close(t.fd)
		return err
	}

	go func() {
		for {
			uapiConn, err := t.uapi.Accept()
			if err != nil {
				return
			}
			go t.device.IpcHandle(uapiConn)
		}
	}()

	err = t.device.Up()
	if err != nil {
		tunSock.Close()
		t.device.Close()
		return err
	}
	log.Debugf("device is ready to use: %s", name)
	return nil
}

func (t *tunDevice) Device() *device.Device {
	return t.device
}

func (t *tunDevice) DeviceName() string {
	return t.name
}

func (t *tunDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunDevice) UpdateAddr(addr WGAddress) error {
	// todo implement
	return nil
}

func (t *tunDevice) Close() (err error) {
	if t.uapi != nil {
		err = t.uapi.Close()
	}

	if t.device != nil {
		t.device.Close()
	}

	return
}
