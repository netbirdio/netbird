package iface

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os"
)

const (
	interfacePrefix = "wg"
)

// assignAddr Adds IP address to the tunnel interface
func assignAddr(iface string, address string) error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = iface

	link := wgLink{
		attrs: &attrs,
	}

	log.Debugf("adding address %s to interface: %s", address, iface)
	addr, _ := netlink.ParseAddr(address)
	err := netlink.AddrAdd(&link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", iface, address)
	} else if err != nil {
		return err
	}
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(&link)
	return err
}
