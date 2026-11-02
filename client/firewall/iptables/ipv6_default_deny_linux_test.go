//go:build privileged

package iptables

import (
	"net/netip"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/fwtest"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func ip6ChainExists(t *testing.T, chain string) bool {
	t.Helper()

	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	require.NoError(t, err, "ip6tables client")
	chains, err := client.ListChains(tableFilter)
	require.NoError(t, err, "list ip6tables chains")
	for _, c := range chains {
		if c == chain {
			return true
		}
	}
	return false
}

// An interface without an IPv6 overlay address still receives IPv6 from its peers, since a
// peer chooses the source addresses it is allowed. With no IPv6 rules to accept it, all of it
// must be dropped, and removing the firewall must give the interface back.
func TestIptablesManagerDropsIPv6WithoutOverlayAddress(t *testing.T) {
	if !firewall.HostHasIPv6() {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("ip6tables not usable: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	require.NoError(t, ns.Dial(t, addr), "control: connection without the firewall")

	mock := &iFaceMock{
		NameFunc: func() string { return ns.IfaceName },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
	manager, err := Create(mock, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, manager.Init(nil))
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = manager.Close(nil)
		}
	})

	assert.True(t, ip6ChainExists(t, chainACLInput), "the IPv6 ACL chain must exist while the firewall runs")
	assert.Error(t, ns.Dial(t, addr), "IPv6 arriving on an interface without an IPv6 overlay address must be dropped")

	require.NoError(t, manager.Close(nil))
	closed = true

	assert.False(t, ip6ChainExists(t, chainACLInput), "Close must remove the IPv6 ACL chain")
	assert.NoError(t, ns.Dial(t, addr), "connection must work again once the firewall is closed")
}

// The IPv6 deny exists exactly when the host has IPv6, and IPv6 rules still require an overlay address.
func TestIptablesManagerIPv6FamilyFollowsHostAndOverlay(t *testing.T) {
	noV6 := &iFaceMock{
		NameFunc: func() string { return "wt-fam" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
	m, err := Create(noV6, iface.DefaultMTU)
	require.NoError(t, err)
	assert.False(t, m.hasIPv6(), "no IPv6 overlay address means no IPv6 rules, NAT or forwarding")
	wantFamily := firewall.HostHasIPv6() && probeIPv6Filtering() == nil
	assert.Equal(t, wantFamily, m.hasV6Family(), "the deny exists when the host has IPv6 and ip6tables works")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, firewall.Network{}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	assert.ErrorIs(t, err, firewall.ErrIPv6NotInitialized, "IPv6 rules are still refused without an overlay address")
}
