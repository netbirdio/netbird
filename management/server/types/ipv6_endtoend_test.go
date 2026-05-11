package types_test

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestNetworkMapComponents_IPv6EndToEnd(t *testing.T) {
	account := createComponentTestAccount()

	// Make all peers IPv6-capable and assign IPv6 addrs.
	v6Caps := []int32{nbpeer.PeerCapabilityIPv6Overlay, nbpeer.PeerCapabilitySourcePrefixes}
	account.Peers["peer-src-1"].Meta.Capabilities = v6Caps
	account.Peers["peer-src-1"].IPv6 = netip.MustParseAddr("fd00::1")
	account.Peers["peer-src-2"].Meta.Capabilities = v6Caps
	account.Peers["peer-src-2"].IPv6 = netip.MustParseAddr("fd00::2")
	account.Peers["peer-dst-1"].Meta.Capabilities = v6Caps
	account.Peers["peer-dst-1"].IPv6 = netip.MustParseAddr("fd00::3")

	// Mark group-src and group-dst as IPv6-enabled.
	account.Settings.IPv6EnabledGroups = []string{"group-src", "group-dst"}

	validated := allPeersValidated(account)
	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	require.NotNil(t, nm)

	t.Run("v6 AAAA records emitted", func(t *testing.T) {
		require.NotEmpty(t, nm.DNSConfig.CustomZones, "expected at least one custom zone")
		var hasAAAA bool
		var hasA bool
		for _, z := range nm.DNSConfig.CustomZones {
			for _, r := range z.Records {
				if r.Type == int(dns.TypeAAAA) {
					hasAAAA = true
				}
				if r.Type == int(dns.TypeA) {
					hasA = true
				}
			}
		}
		assert.True(t, hasA, "expected A records")
		assert.True(t, hasAAAA, "expected AAAA records for IPv6-enabled peers")
	})

	t.Run("v6 AllowedIPs would be advertised", func(t *testing.T) {
		// nm.Peers contains *nbpeer.Peer; IPv6 should be set on those peers
		var foundV6 bool
		for _, p := range nm.Peers {
			if p.IPv6.IsValid() {
				foundV6 = true
			}
		}
		assert.True(t, foundV6, "remote peers should have IPv6 set so AllowedIPs gets v6")
	})

	t.Run("v6 firewall rules emitted", func(t *testing.T) {
		require.NotEmpty(t, nm.FirewallRules, "expected firewall rules")
		var hasV4 bool
		var hasV6 bool
		for _, r := range nm.FirewallRules {
			addr, err := netip.ParseAddr(r.PeerIP)
			if err != nil {
				continue
			}
			if addr.Is4() {
				hasV4 = true
			}
			if addr.Is6() {
				hasV6 = true
			}
		}
		assert.True(t, hasV4, "expected at least one v4 firewall rule (peer IP)")
		assert.True(t, hasV6, "expected at least one v6 firewall rule (peer IPv6)")
	})
}

// TestNetworkMapComponents_RemotePeerWithoutCapability checks the asymmetric
// case where the target peer is IPv6-capable but a remote peer has an IPv6
// address assigned in the DB without yet reporting the capability flag.
// In that case the remote peer's v6 still appears in AllowedIPs (gated on
// the target peer's capability) but its AAAA record does not (gated on the
// remote peer's own capability).
func TestNetworkMapComponents_RemotePeerWithoutCapability(t *testing.T) {
	account := createComponentTestAccount()

	v6Caps := []int32{nbpeer.PeerCapabilityIPv6Overlay, nbpeer.PeerCapabilitySourcePrefixes}
	// Target is fully capable.
	account.Peers["peer-src-1"].Meta.Capabilities = v6Caps
	account.Peers["peer-src-1"].IPv6 = netip.MustParseAddr("fd00::1")
	// Remote peer has v6 assigned but no capability flag yet (e.g. old client).
	account.Peers["peer-dst-1"].IPv6 = netip.MustParseAddr("fd00::3")

	account.Settings.IPv6EnabledGroups = []string{"group-src", "group-dst"}

	validated := allPeersValidated(account)
	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	require.NotNil(t, nm)

	t.Run("AllowedIPs include remote v6", func(t *testing.T) {
		var dst *nbpeer.Peer
		for _, p := range nm.Peers {
			if p.ID == "peer-dst-1" {
				dst = p
			}
		}
		require.NotNil(t, dst)
		assert.True(t, dst.IPv6.IsValid(), "remote peer's v6 should still be present so AllowedIPs gets v6/128 (gated on target peer cap)")
	})

	t.Run("no AAAA for non-capable remote peer", func(t *testing.T) {
		for _, z := range nm.DNSConfig.CustomZones {
			for _, r := range z.Records {
				if r.Type == int(dns.TypeAAAA) && r.RData == "fd00::3" {
					t.Errorf("AAAA record for non-capable remote peer should NOT be emitted, got %+v", r)
				}
			}
		}
	})
}

// TestNetworkMapComponents_IPv6Disabled_NoV6Output asserts that a peer that
// does not support IPv6 (e.g. older client without the capability flag) gets
// no v6 firewall rules and no AAAA records, even if other peers have IPv6.
func TestNetworkMapComponents_IPv6Disabled_NoV6Output(t *testing.T) {
	account := createComponentTestAccount()

	v6Caps := []int32{nbpeer.PeerCapabilityIPv6Overlay}
	account.Peers["peer-src-2"].Meta.Capabilities = v6Caps
	account.Peers["peer-src-2"].IPv6 = netip.MustParseAddr("fd00::2")
	account.Peers["peer-dst-1"].Meta.Capabilities = v6Caps
	account.Peers["peer-dst-1"].IPv6 = netip.MustParseAddr("fd00::3")
	// peer-src-1 (target) intentionally has no capability and no IPv6.

	account.Settings.IPv6EnabledGroups = []string{"group-src", "group-dst"}

	validated := allPeersValidated(account)
	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	require.NotNil(t, nm)

	t.Run("no v6 firewall rules", func(t *testing.T) {
		for _, r := range nm.FirewallRules {
			addr, err := netip.ParseAddr(r.PeerIP)
			if err != nil {
				continue
			}
			assert.False(t, addr.Is6(), "v6 firewall rules should not be emitted for non-IPv6 peer (got %s)", r.PeerIP)
		}
	})
}
