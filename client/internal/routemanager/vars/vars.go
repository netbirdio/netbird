package vars

import (
	"errors"
	"net/netip"
)

var (
	ErrRouteNotFound   = errors.New("route not found")
	ErrRouteNotAllowed = errors.New("route not allowed")

	Defaultv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	Defaultv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

const MinRangeBits = 7
