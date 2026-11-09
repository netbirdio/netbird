package wgaddr

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddress_HostPrefix(t *testing.T) {
	addr := MustParseWGAddress("100.91.96.107/16")

	assert.Equal(t, netip.MustParsePrefix("100.91.96.107/32"), addr.HostPrefix(), "v4 host prefix must be a single host")
	assert.Equal(t, netip.MustParsePrefix("100.91.0.0/16"), addr.Network, "network must keep the overlay prefix length")
	assert.False(t, addr.IPv6HostPrefix().IsValid(), "no v6 overlay means no v6 host prefix")
}

func TestAddress_IPv6HostPrefix(t *testing.T) {
	addr := MustParseWGAddress("100.91.96.107/16")
	addr.IPv6 = netip.MustParseAddr("fd00:1234::1")
	addr.IPv6Net = netip.MustParsePrefix("fd00:1234::/64")

	assert.Equal(t, netip.MustParsePrefix("fd00:1234::1/128"), addr.IPv6HostPrefix(), "v6 host prefix must be a single host")
}
