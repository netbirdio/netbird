//go:build linux && !android

package iface

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/iface/bind"
)

type tunKernelDevice struct {
	name    string
	address WGAddress
	mtu     int

	link *wgLink
}

func newTunDevice(name string, address WGAddress, mtu int) wgTunDevice {
	return &tunKernelDevice{
		name:    name,
		address: address,
		mtu:     mtu,
	}
}

func (t *tunKernelDevice) Create() (wgConfigurer, error) {
	link := newWGLink(t.name)

	// check if interface exists
	l, err := netlink.LinkByName(t.name)
	if err != nil {
		switch err.(type) {
		case netlink.LinkNotFoundError:
			break
		default:
			return nil, err
		}
	}

	// remove if interface exists
	if l != nil {
		err = netlink.LinkDel(link)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("adding device: %s", t.name)
	err = netlink.LinkAdd(link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", t.name)
	} else if err != nil {
		return nil, err
	}

	t.link = link

	err = t.assignAddr()
	if err != nil {
		return nil, err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", t.mtu, t.name)
	err = netlink.LinkSetMTU(link, t.mtu)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", t.name)
		return nil, err
	}

	log.Debugf("bringing up interface: %s", t.name)
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Errorf("error bringing up interface: %s", t.name)
		return nil, err
	}

	configurer := newWGConfigurer(t.name)
	return configurer, nil
}

func (t *tunKernelDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunKernelDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunKernelDevice) DeviceName() string {
	return t.name
}

func (t *tunKernelDevice) IceBind() *bind.ICEBind {
	return nil
}

func (t *tunKernelDevice) Wrapper() *DeviceWrapper {
	return nil
}

func (t *tunKernelDevice) Close() error {
	if t.link != nil {
		_ = t.link.Close()
	}
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (t *tunKernelDevice) assignAddr() error {
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
