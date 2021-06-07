package iface

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	"os"
)

//const (
//	interfacePrefix = "wg"
//)

// assignAddr Adds IP address to the tunnel interface
func assignAddr(address string, tunDevice tun.Device) error {
	var err error
	attrs := netlink.NewLinkAttrs()
	attrs.Name, err = tunDevice.Name()
	if err != nil {
		return err
	}

	link := wgLink{
		attrs: &attrs,
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
