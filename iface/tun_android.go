package iface

import (
	"golang.org/x/sys/unix"

	"github.com/pion/transport/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunDevice struct {
	address    WGAddress
	mtu        int
	tunAdapter TunAdapter

	fd      int
	name    string
	device  *device.Device
	iceBind *bind.ICEBind
}

func newTunDevice(address WGAddress, mtu int, tunAdapter TunAdapter, transportNet transport.Net) *tunDevice {
	return &tunDevice{
		address:    address,
		mtu:        mtu,
		tunAdapter: tunAdapter,
		iceBind:    bind.NewICEBind(transportNet),
	}
}

func (t *tunDevice) Create() error {
	var err error
	t.fd, err = t.tunAdapter.ConfigureInterface(t.address.String(), t.mtu)
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
	t.device = device.NewDevice(tunDevice, t.iceBind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	t.device.DisableSomeRoamingForBrokenMobileSemantics()

	err = t.device.Up()
	if err != nil {
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
	if t.device != nil {
		t.device.Close()
	}

	return
}
