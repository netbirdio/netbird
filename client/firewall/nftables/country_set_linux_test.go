//go:build !android && privileged

package nftables

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// TestNftablesManager_CountrySet loads a country-sized prefix list into the set that a
// country route's NAT rule and route ACL share, the way a routing peer does: the NAT rule
// and the ACL rule create the set, then the ACL fills it.
func TestNftablesManager_CountrySet(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "failed to reset")
	})

	set := fw.NewCountrySet([]string{"US"})
	destination := fw.Network{Set: set}

	require.NoError(t, manager.AddNatRule(fw.RouterPair{
		ID:          "route-us",
		Source:      fw.Network{Prefix: netip.MustParsePrefix("0.0.0.0/0")},
		Destination: destination,
		Masquerade:  true,
		Dynamic:     true,
	}), "add NAT rule")
	_, err = manager.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}, destination,
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add route rule")

	// The US merges to about 127k IPv4 prefixes. Every other /24 keeps them from merging.
	const count = 130_000
	prefixes := make([]netip.Prefix, 0, count)
	addr := netip.MustParseAddr("1.0.0.0")
	for range count {
		prefixes = append(prefixes, netip.PrefixFrom(addr, 24))
		for range 512 {
			addr = addr.Next()
		}
	}

	start := time.Now()
	require.NoError(t, manager.UpdateSet(set, prefixes), "fill the country set")
	t.Logf("loaded %d prefixes in %s", count, time.Since(start))

	conn := &nftables.Conn{}
	nfSet, err := conn.GetSetByName(manager.family4.workTable, set.HashedName())
	require.NoError(t, err, "the set should exist")
	elements, err := conn.GetSetElements(nfSet)
	require.NoError(t, err)

	starts := 0
	for _, element := range elements {
		if !element.IntervalEnd {
			starts++
		}
	}
	assert.Equal(t, count, starts, "every prefix should be in the set")
}

// TestNftablesManager_UpdateSetIPv6Only fills a country set used only by an IPv6 rule, as for a
// route whose sources are all IPv6. No IPv4 rule created the set in the IPv4 table, so the
// update must not look for it there.
func TestNftablesManager_UpdateSetIPv6Only(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	dualStack := &iFaceMock{
		NameFunc: func() string { return "wg-test" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	manager, err := Create(dualStack, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "failed to reset")
	})

	set := fw.NewCountrySet([]string{"US"})
	_, err = manager.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, fw.Network{Set: set},
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add IPv6 route rule")

	prefixes := []netip.Prefix{netip.MustParsePrefix("2001:4860::/32")}
	require.NoError(t, manager.UpdateSet(set, prefixes), "an IPv6-only update must not need an IPv4 set")

	conn := &nftables.Conn{}
	nfSet, err := conn.GetSetByName(manager.family6.workTable, set.HashedName())
	require.NoError(t, err, "the IPv6 set should exist")
	elements, err := conn.GetSetElements(nfSet)
	require.NoError(t, err)
	assert.Len(t, elements, 2, "the prefix should be stored as one interval")
}
