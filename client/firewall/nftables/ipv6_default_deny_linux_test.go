//go:build privileged

package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/fwtest"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func hasIPv6Table(t *testing.T) bool {
	t.Helper()

	tables, err := (&nftables.Conn{}).ListTablesOfFamily(nftables.TableFamilyIPv6)
	require.NoError(t, err, "list ip6 tables")
	for _, table := range tables {
		if table.Name == getTableName() {
			return true
		}
	}
	return false
}

// An interface without an IPv6 overlay address still receives IPv6 from its peers, since a
// peer chooses the source addresses it is allowed. With no IPv6 rules to accept it, all of it
// must be dropped, and removing the firewall must give the interface back.
func TestNftablesManagerDropsIPv6WithoutOverlayAddress(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	if !firewall.HostHasIPv6() {
		t.Skip("host has no IPv6")
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

	assert.True(t, hasIPv6Table(t), "the ip6 table must exist while the firewall runs")
	assert.Error(t, ns.Dial(t, addr), "IPv6 arriving on an interface without an IPv6 overlay address must be dropped")

	require.NoError(t, manager.Close(nil))
	closed = true

	assert.False(t, hasIPv6Table(t), "Close must remove the ip6 table")
	assert.NoError(t, ns.Dial(t, addr), "connection must work again once the firewall is closed")
}

// A host without an IPv6 overlay address on the interface and IPv6 enabled gets the deny, and
// an interface with an overlay address keeps its table and rules as before.
func TestNftablesManagerIPv6FamilyFollowsHostAndOverlay(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	withV6 := &iFaceMock{
		NameFunc: func() string { return "wt-fam" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	m, err := Create(withV6, iface.DefaultMTU)
	require.NoError(t, err)
	assert.True(t, m.hasIPv6(), "an IPv6 overlay address means IPv6 rules apply")
	assert.True(t, m.hasV6Family())

	noV6 := &iFaceMock{
		NameFunc: func() string { return "wt-fam" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
	m, err = Create(noV6, iface.DefaultMTU)
	require.NoError(t, err)
	assert.False(t, m.hasIPv6(), "no IPv6 overlay address means no IPv6 rules, NAT or forwarding")
	assert.Equal(t, firewall.HostHasIPv6(), m.hasV6Family(), "the deny exists exactly when the host has IPv6")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, firewall.Network{}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	assert.ErrorIs(t, err, firewall.ErrIPv6NotInitialized, "IPv6 rules are still refused without an overlay address")
}
