package roundtrip

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
)

// ErrDirectUpstreamBlocked is returned when a direct-upstream dial targets
// an address that is not globally reachable while
// NB_PROXY_DIRECT_UPSTREAM_BLOCK_PRIVATE is set.
var ErrDirectUpstreamBlocked = errors.New("direct upstream address is not allowed")

// blockedUpstreamPrefixes are the ranges that reach the proxy host, its
// cluster or its cloud provider rather than the public internet. NAT64
// and 6to4 addresses are matched by the IPv4 address they embed.
var blockedUpstreamPrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network", including 0.0.0.0
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local, cloud metadata services
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, including broadcast

	// IPv6
	netip.MustParsePrefix("::/96"),          // unspecified, loopback, IPv4-compatible
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo
	netip.MustParsePrefix("2001:2::/48"),    // benchmarking
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("3fff::/20"),      // documentation
	netip.MustParsePrefix("5f00::/16"),      // SRv6 SIDs
	netip.MustParsePrefix("fc00::/7"),       // unique local, including AWS IMDS fd00:ec2::254
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fec0::/10"),      // site-local (deprecated)
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

// isBlockedUpstreamAddr reports whether a guarded direct-upstream dial
// must refuse addr.
func isBlockedUpstreamAddr(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return true
	}

	if nat64Prefix.Contains(addr) {
		b := addr.As16()
		return isBlockedUpstreamAddr(netip.AddrFrom4([4]byte(b[12:16])))
	}
	if sixToFour.Contains(addr) {
		b := addr.As16()
		return isBlockedUpstreamAddr(netip.AddrFrom4([4]byte(b[2:6])))
	}

	for _, p := range blockedUpstreamPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// guardUpstreamDial is a net.Dialer ControlContext that refuses blocked
// addresses. It sees the resolved address of each socket just before
// connect, so DNS rebinding cannot swap the target after the check.
func guardUpstreamDial(_ context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || isBlockedUpstreamAddr(ap.Addr()) {
		return ErrDirectUpstreamBlocked
	}
	return nil
}
