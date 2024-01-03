//go:build linux && !android

package iface

import "github.com/vishvananda/netlink"

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
