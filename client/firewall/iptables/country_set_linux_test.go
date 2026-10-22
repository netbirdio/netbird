//go:build privileged

package iptables

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lrh3321/ipset-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
)

// TestIptablesManager_CountrySet loads a country-sized prefix list into the ipset that a
// country route's NAT rule and route ACL share, the way a routing peer does: the NAT rule
// and the ACL rule create the set, then the ACL fills it.
func TestIptablesManager_CountrySet(t *testing.T) {
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "clear the manager state")
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
	_, err = manager.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.2/32")}, destination,
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add route rule")

	// ipset-go creates hash:net sets with the default maxelem of 65536, which every country
	// but the US stays under. Every other /24 keeps the prefixes from merging.
	const count = 65_000
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

	result, err := ipset.List(set.HashedName())
	require.NoError(t, err, "the ipset should exist")
	assert.Len(t, result.Entries, count, "every prefix should be in the ipset")
}

// TestIptablesManager_CountrySetFull checks that filling an ipset past its 65536 entries stops at
// the first rejected prefix instead of failing each of the remaining ones.
func TestIptablesManager_CountrySetFull(t *testing.T) {
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "clear the manager state")
	})

	set := fw.NewCountrySet([]string{"US"})
	_, err = manager.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.2/32")}, fw.Network{Set: set},
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add route rule")

	const count = 70_000
	prefixes := make([]netip.Prefix, 0, count)
	addr := netip.MustParseAddr("1.0.0.0")
	for range count {
		prefixes = append(prefixes, netip.PrefixFrom(addr, 24))
		for range 512 {
			addr = addr.Next()
		}
	}

	err = manager.UpdateSet(set, prefixes)
	require.Error(t, err, "a set past its maxelem must report the failure")
	assert.Equal(t, 1, strings.Count(err.Error(), "add prefix to ipset:"),
		"filling should stop at the first prefix the full set rejects")
}
