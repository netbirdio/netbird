package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestPeerIPv6Allowed(t *testing.T) {
	account := &Account{
		Groups: map[string]*Group{
			"group-all":   {ID: "group-all", Name: "All", Peers: []string{"peer1", "peer2", "peer3"}},
			"group-devs":  {ID: "group-devs", Name: "Devs", Peers: []string{"peer1", "peer2"}},
			"group-infra": {ID: "group-infra", Name: "Infra", Peers: []string{"peer2", "peer3"}},
			"group-empty": {ID: "group-empty", Name: "Empty", Peers: []string{}},
		},
		Settings: &Settings{},
	}

	tests := []struct {
		name          string
		enabledGroups []string
		peerID        string
		expected      bool
	}{
		{
			name:          "empty groups list disables IPv6 for all",
			enabledGroups: []string{},
			peerID:        "peer1",
			expected:      false,
		},
		{
			name:          "All group enables IPv6 for everyone",
			enabledGroups: []string{"group-all"},
			peerID:        "peer1",
			expected:      true,
		},
		{
			name:          "peer in enabled group gets IPv6",
			enabledGroups: []string{"group-devs"},
			peerID:        "peer1",
			expected:      true,
		},
		{
			name:          "peer not in any enabled group denied IPv6",
			enabledGroups: []string{"group-devs"},
			peerID:        "peer3",
			expected:      false,
		},
		{
			name:          "peer in multiple groups, one enabled",
			enabledGroups: []string{"group-infra"},
			peerID:        "peer2",
			expected:      true,
		},
		{
			name:          "peer in multiple groups, other one enabled",
			enabledGroups: []string{"group-devs"},
			peerID:        "peer2",
			expected:      true,
		},
		{
			name:          "multiple enabled groups, peer in one",
			enabledGroups: []string{"group-devs", "group-infra"},
			peerID:        "peer1",
			expected:      true,
		},
		{
			name:          "multiple enabled groups, peer in both",
			enabledGroups: []string{"group-devs", "group-infra"},
			peerID:        "peer2",
			expected:      true,
		},
		{
			name:          "nonexistent group ID in enabled list",
			enabledGroups: []string{"group-deleted"},
			peerID:        "peer1",
			expected:      false,
		},
		{
			name:          "empty group in enabled list",
			enabledGroups: []string{"group-empty"},
			peerID:        "peer1",
			expected:      false,
		},
		{
			name:          "unknown peer ID",
			enabledGroups: []string{"group-all"},
			peerID:        "peer-unknown",
			expected:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account.Settings.IPv6EnabledGroups = tc.enabledGroups
			result := account.PeerIPv6Allowed(tc.peerID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIPv6RecalculationOnGroupChange(t *testing.T) {
	peerWithV6 := func(id string, v6 string) *nbpeer.Peer {
		p := &nbpeer.Peer{
			ID: id,
			IP: netip.MustParseAddr("100.64.0.1"),
		}
		if v6 != "" {
			p.IPv6 = netip.MustParseAddr(v6)
		}
		return p
	}

	t.Run("peer loses IPv6 when removed from enabled groups", func(t *testing.T) {
		peer := peerWithV6("peer1", "fd00::1")

		account := &Account{
			Peers: map[string]*nbpeer.Peer{"peer1": peer},
			Groups: map[string]*Group{
				"group-a": {ID: "group-a", Peers: []string{"peer1"}},
				"group-b": {ID: "group-b", Peers: []string{}},
			},
			Settings: &Settings{
				IPv6EnabledGroups: []string{"group-a"},
			},
		}

		assert.True(t, account.PeerIPv6Allowed("peer1"), "peer should be allowed before change")

		// Move peer out of enabled group
		account.Groups["group-a"].Peers = []string{}
		account.Groups["group-b"].Peers = []string{"peer1"}

		assert.False(t, account.PeerIPv6Allowed("peer1"), "peer should be denied after group change")
	})

	t.Run("peer gains IPv6 when added to enabled group", func(t *testing.T) {
		peer := peerWithV6("peer1", "")

		account := &Account{
			Peers: map[string]*nbpeer.Peer{"peer1": peer},
			Groups: map[string]*Group{
				"group-a": {ID: "group-a", Peers: []string{}},
				"group-b": {ID: "group-b", Peers: []string{"peer1"}},
			},
			Settings: &Settings{
				IPv6EnabledGroups: []string{"group-a"},
			},
		}

		assert.False(t, account.PeerIPv6Allowed("peer1"), "peer should be denied before change")

		// Add peer to enabled group
		account.Groups["group-a"].Peers = []string{"peer1"}

		assert.True(t, account.PeerIPv6Allowed("peer1"), "peer should be allowed after joining enabled group")
	})

	t.Run("peer in two groups, one leaves enabled list", func(t *testing.T) {
		peer := peerWithV6("peer1", "fd00::1")

		account := &Account{
			Peers: map[string]*nbpeer.Peer{"peer1": peer},
			Groups: map[string]*Group{
				"group-a": {ID: "group-a", Peers: []string{"peer1"}},
				"group-b": {ID: "group-b", Peers: []string{"peer1"}},
			},
			Settings: &Settings{
				IPv6EnabledGroups: []string{"group-a", "group-b"},
			},
		}

		assert.True(t, account.PeerIPv6Allowed("peer1"))

		// Remove group-a from enabled list, peer still in group-b
		account.Settings.IPv6EnabledGroups = []string{"group-b"}

		assert.True(t, account.PeerIPv6Allowed("peer1"), "peer should still be allowed via group-b")
	})

	t.Run("peer in two groups, both leave enabled list", func(t *testing.T) {
		peer := peerWithV6("peer1", "fd00::1")

		account := &Account{
			Peers: map[string]*nbpeer.Peer{"peer1": peer},
			Groups: map[string]*Group{
				"group-a": {ID: "group-a", Peers: []string{"peer1"}},
				"group-b": {ID: "group-b", Peers: []string{"peer1"}},
			},
			Settings: &Settings{
				IPv6EnabledGroups: []string{"group-a", "group-b"},
			},
		}

		assert.True(t, account.PeerIPv6Allowed("peer1"))

		// Clear all enabled groups
		account.Settings.IPv6EnabledGroups = []string{}

		assert.False(t, account.PeerIPv6Allowed("peer1"), "peer should be denied when no groups enabled")
	})

	t.Run("enabling a group gives only its peers IPv6", func(t *testing.T) {
		account := &Account{
			Peers: map[string]*nbpeer.Peer{
				"peer1": peerWithV6("peer1", ""),
				"peer2": peerWithV6("peer2", ""),
				"peer3": peerWithV6("peer3", ""),
			},
			Groups: map[string]*Group{
				"group-devs":  {ID: "group-devs", Peers: []string{"peer1", "peer2"}},
				"group-infra": {ID: "group-infra", Peers: []string{"peer2", "peer3"}},
			},
			Settings: &Settings{
				IPv6EnabledGroups: []string{"group-devs"},
			},
		}

		assert.True(t, account.PeerIPv6Allowed("peer1"), "peer1 in devs")
		assert.True(t, account.PeerIPv6Allowed("peer2"), "peer2 in devs")
		assert.False(t, account.PeerIPv6Allowed("peer3"), "peer3 not in devs")

		// Add infra group
		account.Settings.IPv6EnabledGroups = []string{"group-devs", "group-infra"}

		assert.True(t, account.PeerIPv6Allowed("peer1"), "peer1 still in devs")
		assert.True(t, account.PeerIPv6Allowed("peer2"), "peer2 in both")
		assert.True(t, account.PeerIPv6Allowed("peer3"), "peer3 now in infra")
	})
}
