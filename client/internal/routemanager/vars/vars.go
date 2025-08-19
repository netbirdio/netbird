package vars

import (
	"errors"
	"net/netip"
)

const MinRangeBits = 7

var (
	ErrRouteNotFound   = errors.New("route not found")
	ErrRouteNotAllowed = errors.New("route not allowed")

	Defaultv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	Defaultv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

	ExitNodeCIDR = "0.0.0.0/0"
)
