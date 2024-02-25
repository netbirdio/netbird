//go:build linux && !android

package iface

import (
	"fmt"
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunUSPDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	mtu     int
	iceBind *bind.ICEBind

	device     *device.Device
	wrapper    *DeviceWrapper
	udpMux     *bind.UniversalUDPMuxDefault
	configurer wgConfigurer
}

func newTunUSPDevice(name string, address WGAddress, port int, key string, mtu int, transportNet transport.Net) wgTunDevice {
	log.Infof("using userspace bind mode")
	return &tunUSPDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet),
	}
}

func (t *tunUSPDevice) Create() (wgConfigurer, error) {
	log.Info("create tun interface")
	tunIface, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		log.Debugf("failed to create tun unterface (%s, %d): %s", t.name, t.mtu, err)
		return nil, err
	}
	t.wrapper = newDeviceWrapper(tunIface)

	// We need to create a wireguard-go device and listen to configuration requests
	t.device = device.NewDevice(
		t.wrapper,
		t.iceBind,
		device.NewLogger(device.LogLevelSilent, "[netbird] "),
	)

	err = t.assignAddr()
	if err != nil {
		t.device.Close()
		return nil, err
	}

	t.configurer = newWGUSPConfigurer(t.device, t.name)
	err = t.configurer.configureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.close()
		return nil, err
	}
	return t.configurer, nil
}

func (t *tunUSPDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
	if t.device == nil {
		return nil, fmt.Errorf("device is not ready yet")
	}

	err := t.device.Up()
	if err != nil {
		return nil, err
	}

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		return nil, err
	}
	t.udpMux = udpMux

	log.Debugf("device is ready to use: %s", t.name)
	return udpMux, nil
}

func (t *tunUSPDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunUSPDevice) UpdateAddr6(address6 *WGAddress) error {
	if address6 == nil {
		return nil
	}
	return fmt.Errorf("IPv6 is not supported on this operating system")
}

func (t *tunUSPDevice) Close() error {
	if t.configurer != nil {
		t.configurer.close()
	}

	if t.device != nil {
		t.device.Close()
	}

	if t.udpMux != nil {
		return t.udpMux.Close()
	}
	return nil
}

func (t *tunUSPDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunUSPDevice) WgAddress6() *WGAddress {
	return nil
}

func (t *tunUSPDevice) DeviceName() string {
	return t.name
}

func (t *tunUSPDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}

// assignAddr Adds IP address to the tunnel interface
func (t *tunUSPDevice) assignAddr() error {
	link := newWGLink(t.name)

	//delete existing addresses
	list, err := netlink.AddrList(link, 0)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		for _, a := range list {
			addr := a
			err = netlink.AddrDel(link, &addr)
			if err != nil {
				return err
			}
		}
	}

	log.Debugf("adding address %s to interface: %s", t.address.String(), t.name)
	addr, _ := netlink.ParseAddr(t.address.String())
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", t.name, t.address.String())
	} else if err != nil {
		return err
	}
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}
