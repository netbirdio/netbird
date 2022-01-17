package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os"
)

type NativeLink struct {
	Link *netlink.Link
}

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {

	if WireguardModExists() {
		log.Debug("using kernel Wireguard module")
		return w.CreateWithKernel()
	} else {
		return w.CreateWithUserspace()
	}
}

// CreateWithKernel Creates a new Wireguard interface using kernel Wireguard module.
// Works for Linux and offers much better network performance
func (w *WGIface) CreateWithKernel() error {

	link := newWGLink(w.Name)

	// check if interface exists
	l, err := netlink.LinkByName(w.Name)
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

	log.Debugf("adding device: %s", w.Name)
	err = netlink.LinkAdd(link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", w.Name)
	} else if err != nil {
		return err
	}

	w.Interface = link

	err = w.assignAddr()
	if err != nil {
		return err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", w.MTU, w.Name)
	err = netlink.LinkSetMTU(link, w.MTU)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", w.Name)
		return err
	}

	log.Debugf("bringing up interface: %s", w.Name)
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Errorf("error bringing up interface: %s", w.Name)
		return err
	}

	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (w *WGIface) assignAddr() error {

	mask, _ := w.Address.Network.Mask.Size()
	address := fmt.Sprintf("%s/%d", w.Address.IP.String(), mask)

	link := newWGLink(w.Name)

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

	log.Debugf("adding address %s to interface: %s", address, w.Name)
	addr, _ := netlink.ParseAddr(address)
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", w.Name, address)
	} else if err != nil {
		return err
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
