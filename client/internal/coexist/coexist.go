// Package coexist holds the rules that let several NetBird installations run on
// one machine without talking to each other. Each installation decides from its
// own role and from what it sees in the operating system: the other NetBird
// adapters, their addresses and their routes.
package coexist

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/instance"
)

// overlayInterfacePrefix starts the name of every NetBird adapter. The ICE
// interface blacklist already relies on it.
const overlayInterfacePrefix = "wt"

// IsOverlayInterface reports whether an adapter name is a NetBird adapter.
func IsOverlayInterface(name string) bool {
	return strings.HasPrefix(name, overlayInterfacePrefix)
}

// Adapter is another installation's overlay adapter and its address prefixes.
type Adapter struct {
	Name     string
	Prefixes []netip.Prefix
}

// OverlayConflict is an overlap between this installation's overlay and an
// address prefix on another NetBird adapter.
type OverlayConflict struct {
	Adapter string
	Own     netip.Prefix
	Other   netip.Prefix
}

func (c OverlayConflict) Error() string {
	return fmt.Sprintf("the overlay %s overlaps %s on the NetBird adapter %s; this secondary installation stays "+
		"disconnected until one network changes its range", c.Own, c.Other, c.Adapter)
}

// CheckOverlay refuses to bring up a secondary installation whose overlay
// prefix overlaps an address prefix of another NetBird adapter: one of the two
// networks would break completely. A primary is not checked. The check fails
// closed: when the adapters cannot be listed, the secondary does not connect.
func CheckOverlay(inst instance.Instance, ownIface string, addr wgaddr.Address) error {
	if !inst.IsSecondary() {
		return nil
	}
	others, err := OtherOverlayAdapters(ownIface)
	if err != nil {
		return fmt.Errorf("list NetBird adapters to check for an overlapping overlay: %w", err)
	}
	if c, ok := FindOverlayConflict(OverlayPrefixes(addr), others); ok {
		return c
	}
	return nil
}

// FindOverlayConflict returns the first overlap between own and the adapters'
// prefixes.
func FindOverlayConflict(own []netip.Prefix, others []Adapter) (OverlayConflict, bool) {
	for _, a := range others {
		for _, other := range a.Prefixes {
			for _, p := range own {
				if p.Overlaps(other) {
					return OverlayConflict{Adapter: a.Name, Own: p, Other: other}, true
				}
			}
		}
	}
	return OverlayConflict{}, false
}

// OtherOverlayAdapters lists the NetBird adapters other than ownIface, with the
// prefixes of their addresses.
func OtherOverlayAdapters(ownIface string) ([]Adapter, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for _, iface := range ifaces {
		if iface.Name == ownIface || !IsOverlayInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", iface.Name, err)
		}
		a := Adapter{Name: iface.Name}
		for _, addr := range addrs {
			if p, ok := addrPrefix(addr); ok {
				a.Prefixes = append(a.Prefixes, p)
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// PartialOverlaps returns the routes on other NetBird adapters that are more
// specific than, and inside, one of own: longest-prefix routing sends that part
// of the overlay to the other network. This may be intended, so it is only
// reported.
func PartialOverlaps(own []netip.Prefix, otherRoutes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range otherRoutes {
		for _, p := range own {
			if r.Bits() > p.Bits() && p.Contains(r.Addr()) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// IdenticalRoutes returns the prefixes of own that another NetBird adapter
// routes too. The primary wins those through its lower interface metric.
func IdenticalRoutes(own, otherRoutes []netip.Prefix) []netip.Prefix {
	others := make(map[netip.Prefix]struct{}, len(otherRoutes))
	for _, r := range otherRoutes {
		others[r.Masked()] = struct{}{}
	}
	var out []netip.Prefix
	for _, p := range own {
		if _, ok := others[p.Masked()]; ok {
			out = append(out, p)
		}
	}
	return out
}

// OverlayPrefixes returns the overlay prefixes of an address, v4 and, when the
// installation has one, v6.
func OverlayPrefixes(addr wgaddr.Address) []netip.Prefix {
	var out []netip.Prefix
	if addr.Network.IsValid() {
		out = append(out, addr.Network.Masked())
	}
	if addr.IPv6Net.IsValid() {
		out = append(out, addr.IPv6Net.Masked())
	}
	return out
}

func addrPrefix(a net.Addr) (netip.Prefix, bool) {
	ipnet, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	ip, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipnet.Mask.Size()
	ip = ip.Unmap()
	if ip.IsLinkLocalUnicast() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, ones).Masked(), true
}
