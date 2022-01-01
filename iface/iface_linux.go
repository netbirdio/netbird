package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"os"
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func Create(iface string, address string) error {
	if WireguardModExists() {
		log.Debug("using kernel Wireguard module")
		return CreateWithKernel(iface, address)
	} else {
		return CreateWithUserspace(iface, address)
	}
}

// CreateWithKernel Creates a new Wireguard interface using kernel Wireguard module.
// Works for Linux and offers much better network performance
func CreateWithKernel(iface string, address string) error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = iface

	link := wgLink{
		attrs: &attrs,
	}

	// check if interface exists
	l, err := netlink.LinkByName(iface)
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
		err = netlink.LinkDel(&link)
		if err != nil {
			return err
		}
	}

	log.Debugf("adding device: %s", iface)
	err = netlink.LinkAdd(&link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", iface)
	} else if err != nil {
		return err
	}

	err = assignAddr(address, iface)
	if err != nil {
		return err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", defaultMTU, iface)
	err = netlink.LinkSetMTU(&link, defaultMTU)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", iface)
		return err
	}

	log.Debugf("bringing up interface: %s", iface)
	err = netlink.LinkSetUp(&link)
	if err != nil {
		log.Errorf("error bringing up interface: %s", iface)
		return err
	}

	return nil
}

// assignAddr Adds IP address to the tunnel interface
func assignAddr(address, name string) error {
	var err error
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name

	link := wgLink{
		attrs: &attrs,
	}

	//delete existing addresses
	list, err := netlink.AddrList(&link, 0)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		for _, a := range list {
			err = netlink.AddrDel(&link, &a)
			if err != nil {
				return err
			}
		}
	}

	log.Debugf("adding address %s to interface: %s", address, attrs.Name)
	addr, _ := netlink.ParseAddr(address)
	err = netlink.AddrAdd(&link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", attrs.Name, address)
	} else if err != nil {
		return err
	}
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(&link)
	return err
}

type wgLink struct {
	attrs *netlink.LinkAttrs
}

// Attrs returns the Wireguard's default attributes
func (w *wgLink) Attrs() *netlink.LinkAttrs {
	return w.attrs
}

// Type returns the interface type
func (w *wgLink) Type() string {
	return "wireguard"
}

// Closes the tunnel interface
func Close() error {

	if tunIface != nil {
		return CloseWithUserspace()
	} else {
		var iface = ""
		wg, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wg.Close()
		devList, err := wg.Devices()
		if err != nil {
			return err
		}
		for _, wgDev := range devList {
			// todo check after move the WgPort constant to the client
			if wgDev.ListenPort == WgPort {
				iface = wgDev.Name
				break
			}
		}
		if iface == "" {
			return fmt.Errorf("Wireguard Interface not found")
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = iface

		link := wgLink{
			attrs: &attrs,
		}
		return netlink.LinkDel(&link)
	}
}
