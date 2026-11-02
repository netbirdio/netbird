//go:build privileged

package iptables

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/fwtest"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/statemanager"
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

func overlayOnlyV4(ifaceName string) *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return ifaceName },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
}

// An interface without an IPv6 overlay address still receives IPv6 from its peers, since a
// peer chooses the source addresses it is allowed. With no IPv6 rules to accept it, all of it
// must be dropped, and removing the firewall must give the interface back.
func TestIptablesManagerDropsIPv6WithoutOverlayAddress(t *testing.T) {
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("ip6tables not usable: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	ns.WaitDial(t, addr, "control: connection without the firewall")

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = manager.Close(nil)
		}
	})
	require.NoError(t, manager.Init(nil))

	assert.True(t, ip6ChainExists(t, chainACLInput), "the IPv6 ACL chain must exist while the firewall runs")
	assert.Error(t, ns.Dial(addr), "IPv6 arriving on an interface without an IPv6 overlay address must be dropped")

	require.NoError(t, manager.Close(nil))
	closed = true

	assert.False(t, ip6ChainExists(t, chainACLInput), "Close must remove the IPv6 ACL chain")
	ns.WaitDial(t, addr, "connection must work again once the firewall is closed")
}

// After a crash the saved state is what removes the firewall. Everything the IPv6 deny put in
// place has to go, even if the host looks different when the cleanup runs than it did when the
// firewall started.
func TestIptablesManagerCrashCleanupRemovesIPv6Deny(t *testing.T) {
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("ip6tables not usable: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	ns.WaitDial(t, addr, "control: connection without the firewall")

	statePath := filepath.Join(t.TempDir(), "state.json")
	sm := statemanager.New(statePath)

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { _ = manager.Close(nil) })
	require.NoError(t, manager.Init(sm))
	require.NoError(t, sm.PersistState(context.Background()), "persist state")

	require.True(t, ip6ChainExists(t, chainACLInput), "the IPv6 ACL chain must exist while the firewall runs")
	require.Error(t, ns.Dial(addr), "IPv6 must be dropped while the firewall runs")

	// The process is gone without closing the firewall. The new run finds the saved state and
	// cleans up, and the host has no IPv6 by then.
	hostHasIPv6 = func(string) bool { return false }
	t.Cleanup(func() { hostHasIPv6 = firewall.HostHasIPv6 })

	recovered := statemanager.New(statePath)
	recovered.RegisterState(&ShutdownState{})
	require.NoError(t, recovered.PerformCleanup(), "crash cleanup")

	assert.False(t, ip6ChainExists(t, chainACLInput), "crash cleanup must remove the IPv6 ACL chain")
	ns.WaitDial(t, addr, "connection must work again after the crash cleanup")

	require.NoError(t, recovered.PersistState(context.Background()))
	names, err := recovered.GetSavedStateNames()
	require.NoError(t, err)
	assert.NotContains(t, names, (&ShutdownState{}).Name(), "the state must be deleted once the cleanup succeeded")
}

// The IPv6 deny exists exactly when the host has IPv6, and IPv6 rules still require an overlay address.
func TestIptablesManagerIPv6FamilyFollowsHostAndOverlay(t *testing.T) {
	m, err := Create(overlayOnlyV4("wt-fam"), iface.DefaultMTU)
	require.NoError(t, err)
	assert.False(t, m.hasIPv6(), "no IPv6 overlay address means no IPv6 rules, NAT or forwarding")
	wantFamily := hostHasIPv6("wt-fam") && probeIPv6Filtering() == nil
	assert.Equal(t, wantFamily, m.hasV6Family(), "the deny exists when the host has IPv6 and ip6tables works")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, firewall.Network{}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	assert.ErrorIs(t, err, firewall.ErrIPv6NotInitialized, "IPv6 rules are still refused without an overlay address")
}

// The escape hatch leaves IPv6 on an interface without an IPv6 overlay address to the host.
func TestIptablesManagerAllowUnfilteredIPv6(t *testing.T) {
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("ip6tables not usable: %v", err)
	}
	t.Setenv(firewall.EnvAllowUnfilteredIPv6, "true")

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { _ = manager.Close(nil) })
	require.NoError(t, manager.Init(nil))

	assert.False(t, manager.hasV6Family(), "no IPv6 family when the operator allows unfiltered IPv6")
	assert.False(t, ip6ChainExists(t, chainACLInput), "no IPv6 ACL chain when the operator allows unfiltered IPv6")
	ns.WaitDial(t, addr, "IPv6 is left to the host's rules")
}
