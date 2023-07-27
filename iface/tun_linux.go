//go:build linux && !android

package iface

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func (c *tunDevice) Create() error {
	if WireGuardModuleIsLoaded() {
		log.Infof("create tun interface with kernel WireGuard support: %s", c.DeviceName())
		return c.createWithKernel()
	}

	if !tunModuleIsLoaded() {
		return fmt.Errorf("couldn't check or load tun module")
	}
	log.Infof("create tun interface with userspace WireGuard support: %s", c.DeviceName())
	var err error
	c.netInterface, err = c.createWithUserspace()
	if err != nil {
		return err
	}

	return c.assignAddr()

}

// createWithKernel Creates a new WireGuard interface using kernel WireGuard module.
// Works for Linux and offers much better network performance
func (c *tunDevice) createWithKernel() error {

	link := newWGLink(c.name)

	// check if interface exists
	l, err := netlink.LinkByName(c.name)
	if err != nil {
		switch err.(type) {
		case netlink.LinkNotFoundError:
			break
		default:
			return err
		}
	}

	// remove if interface exists
	if l != nil {
		err = netlink.LinkDel(link)
		if err != nil {
			return err
		}
	}

	log.Debugf("adding device: %s", c.name)
	err = netlink.LinkAdd(link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", c.name)
	} else if err != nil {
		return err
	}

	c.netInterface = link

	err = c.assignAddr()
	if err != nil {
		return err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", c.mtu, c.name)
	err = netlink.LinkSetMTU(link, c.mtu)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", c.name)
		return err
	}

	log.Debugf("bringing up interface: %s", c.name)
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Errorf("error bringing up interface: %s", c.name)
		return err
	}

	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (c *tunDevice) assignAddr() error {
	link := newWGLink(c.name)

	//delete existing addresses
	list, err := netlink.AddrList(link, 0)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		for _, a := range list {
			err = netlink.AddrDel(link, &a)
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

	// Configure the optional additional IPv6 address if available.
	if c.address6 != nil {
		log.Debugf("adding IPv6 address %s to interface: %s", c.address6.String(), c.name)
		addr6, _ := netlink.ParseAddr(c.address6.String())
		err = netlink.AddrAdd(link, addr6)
		if os.IsExist(err) {
			log.Infof("interface %s already has the address: %s", c.name, c.address.String())
		} else if err != nil {
			return err
		}
	}

	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}

type wgLink struct {
	attrs *netlink.LinkAttrs
}

func newWGLink(name string) *wgLink {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name

	return &wgLink{
		attrs: &attrs,
	}
}

// Attrs returns the Wireguard's default attributes
func (l *wgLink) Attrs() *netlink.LinkAttrs {
	return l.attrs
}

// Type returns the interface type
func (l *wgLink) Type() string {
	return "wireguard"
}

// Close deletes the link interface
func (l *wgLink) Close() error {
	return netlink.LinkDel(l)
}
