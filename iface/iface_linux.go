package iface

import (
	"errors"
	"math"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type NativeLink struct {
	Link *netlink.Link
}

func WireguardModExists() bool {
	link := newWGLink("mustnotexist")

	// We willingly try to create a device with an invalid
	// MTU here as the validation of the MTU will be performed after
	// the validation of the link kind and hence allows us to check
	// for the existance of the wireguard module without actually
	// creating a link.
	//
	// As a side-effect, this will also let the kernel lazy-load
	// the wireguard module.
	link.attrs.MTU = math.MaxInt

	err := netlink.LinkAdd(link)

	return errors.Is(err, syscall.EINVAL)
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if WireguardModExists() {
		log.Info("using kernel WireGuard")
		return w.createWithKernel()
	} else {
		log.Info("using userspace WireGuard")
		return w.createWithUserspace()
	}
}

// createWithKernel Creates a new Wireguard interface using kernel Wireguard module.
// Works for Linux and offers much better network performance
func (w *WGIface) createWithKernel() error {

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

	log.Debugf("adding address %s to interface: %s", w.Address.String(), w.Name)
	addr, _ := netlink.ParseAddr(w.Address.String())
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", w.Name, w.Address.String())
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
