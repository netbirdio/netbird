//go:build linux && !android

package iface

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

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

func (l *wgLink) recreate() error {
	name := l.attrs.Name

	// check if interface exists
	link, err := netlink.LinkByName(name)
	if err != nil {
		switch err.(type) {
		case netlink.LinkNotFoundError:
			break
		default:
			return fmt.Errorf("link by name: %w", err)
		}
	}

	// remove if interface exists
	if link != nil {
		err = netlink.LinkDel(l)
		if err != nil {
			return err
		}
	}

	log.Debugf("adding device: %s", name)
	err = netlink.LinkAdd(l)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", name)
	} else if err != nil {
		return fmt.Errorf("link add: %w", err)
	}

	return nil
}

func (l *wgLink) setMTU(mtu int) error {
	if err := netlink.LinkSetMTU(l, mtu); err != nil {
		log.Errorf("error setting MTU on interface: %s", l.attrs.Name)

		return fmt.Errorf("link set mtu: %w", err)
	}

	return nil
}

func (l *wgLink) up() error {
	if err := netlink.LinkSetUp(l); err != nil {
		log.Errorf("error bringing up interface: %s", l.attrs.Name)
		return fmt.Errorf("link setup: %w", err)
	}

	return nil
}

func (l *wgLink) assignAddr(address WGAddress) error {
	//delete existing addresses
	list, err := netlink.AddrList(l, 0)
	if err != nil {
		return fmt.Errorf("list addr: %w", err)
	}

	if len(list) > 0 {
		for _, a := range list {
			addr := a
			err = netlink.AddrDel(l, &addr)
			if err != nil {
				return fmt.Errorf("del addr: %w", err)
			}
		}
	}

	name := l.attrs.Name
	addrStr := address.String()

	log.Debugf("adding address %s to interface: %s", addrStr, name)

	addr, err := netlink.ParseAddr(addrStr)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}

	err = netlink.AddrAdd(l, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", name, addrStr)
	} else if err != nil {
		return fmt.Errorf("add addr: %w", err)
	}

	// On linux, the link must be brought up
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link setup: %w", err)
	}

	return nil
}
