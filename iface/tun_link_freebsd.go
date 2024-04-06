package iface

import (
	"fmt"

	"github.com/netbirdio/netbird/iface/freebsd"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type wgLink struct {
	name string
}

func newWGLink(name string) *wgLink {
	return &wgLink{
		name: name
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

func (l *wgLink) assignAddr(address WGAddress) error {
	link, err := freebsd.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}

	ip := address.IP.String()
	mask := "0x" + t.address.Network.Mask.String()

	log.Infof("assign addr %s mask %s to %s interface", ip, mask, l.name)

	err = link.AssignAddr(ip, mask)
	if err != nil {
		return fmt.Errorf("assign addr: %w", err)
	}

	err = link.Up()
	if err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}
