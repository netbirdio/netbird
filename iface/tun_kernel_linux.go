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

func (c *tunKernelDevice) Create() (wgConfigurer, error) {
	link := newWGLink(c.name)

	// check if interface exists
	l, err := netlink.LinkByName(c.name)
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

	log.Debugf("adding device: %s", c.name)
	err = netlink.LinkAdd(link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", c.name)
	} else if err != nil {
		return nil, err
	}

	c.link = link

	err = c.assignAddr()
	if err != nil {
		return nil, err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", c.mtu, c.name)
	err = netlink.LinkSetMTU(link, c.mtu)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", c.name)
		return nil, err
	}

	log.Debugf("bringing up interface: %s", c.name)
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Errorf("error bringing up interface: %s", c.name)
		return nil, err
	}

	configurer := newWGConfigurer(c.name)
	return configurer, nil
}

func (c *tunKernelDevice) UpdateAddr(address WGAddress) error {
	c.address = address
	return c.assignAddr()
}

func (c *tunKernelDevice) WgAddress() WGAddress {
	return c.address
}

func (c *tunKernelDevice) DeviceName() string {
	return c.name
}

func (c *tunKernelDevice) IceBind() *bind.ICEBind {
	return nil
}

func (c *tunKernelDevice) Wrapper() *DeviceWrapper {
	return nil
}

func (c *tunKernelDevice) Close() error {
	if c.link != nil {
		_ = c.link.Close()
	}
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (c *tunKernelDevice) assignAddr() error {
	link := newWGLink(c.name)

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

	log.Debugf("adding address %s to interface: %s", c.address.String(), c.name)
	addr, _ := netlink.ParseAddr(c.address.String())
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", c.name, c.address.String())
	} else if err != nil {
		return err
	}
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}
