//go:build ios
// +build ios

package iface

import (
	"os"

	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	address    WGAddress
	mtu        int
	tunAdapter TunAdapter
	iceBind    *bind.ICEBind

	fd      int
	name    string
	device  *device.Device
	wrapper *DeviceWrapper
}

func newTunDevice(name string, address WGAddress, mtu int, tunAdapter TunAdapter, transportNet transport.Net) *tunDevice {
	return &tunDevice{
		name:       name,
		address:    address,
		mtu:        mtu,
		tunAdapter: tunAdapter,
		iceBind:    bind.NewICEBind(transportNet),
	}
}

func (t *tunDevice) Create(tunFd int32) error {
	log.Infof("create tun interface")

	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		log.Errorf("Unable to dup tun fd: %v", err)
		return err
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		log.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return err
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		log.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return err
	}

	t.wrapper = newDeviceWrapper(tun)
	log.Debug("Attaching to interface")
	t.device = device.NewDevice(t.wrapper, t.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	// without this property mobile devices can discover remote endpoints if the configured one was wrong.
	// this helps with support for the older NetBird clients that had a hardcoded direct mode
	// t.device.DisableSomeRoamingForBrokenMobileSemantics()

	err = t.device.Up()
	if err != nil {
		t.device.Close()
		return err
	}
	log.Debugf("device is ready to use: %s", t.name)
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
	if t.device != nil {
		t.device.Close()
	}

	return
}
