package server

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peerA": {
				ID:     "peerA",
				IP:     net.ParseIP("100.65.14.88"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerB": {
				ID:     "peerB",
				IP:     net.ParseIP("100.65.80.39"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerC": {
				ID:     "peerC",
				IP:     net.ParseIP("100.65.254.139"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerD": {
				ID:     "peerD",
				IP:     net.ParseIP("100.65.62.5"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerE": {
				ID:     "peerE",
				IP:     net.ParseIP("100.65.32.206"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerF": {
				ID:     "peerF",
				IP:     net.ParseIP("100.65.250.202"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerG": {
				ID:     "peerG",
				IP:     net.ParseIP("100.65.13.186"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerH": {
				ID:     "peerH",
				IP:     net.ParseIP("100.65.29.55"),
				Status: &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*Group{
			"GroupAll": {
				ID:   "GroupAll",
				Name: "All",
				Peers: []string{
					"peerB",
					"peerA",
					"peerD",
					"peerC",
					"peerE",
					"peerF",
					"peerG",
					"peerH",
				},
			},
			"GroupSwarm": {
				ID:   "GroupSwarm",
				Name: "swarm",
				Peers: []string{
					"peerB",
					"peerA",
					"peerD",
					"peerE",
					"peerG",
					"peerH",
				},
			},
		},
		Policies: []*Policy{
			{
				ID:          "RuleDefault",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Enabled:     true,
				Rules: []*PolicyRule{
					{
						ID:            "RuleDefault",
						Name:          "Default",
						Description:   "This is a default rule that allows connections between all the resources",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      PolicyRuleProtocolALL,
						Action:        PolicyTrafficActionAccept,
						Sources: []string{
							"GroupAll",
						},
						Destinations: []string{
							"GroupAll",
						},
					},
				},
			},
			{
				ID:          "RuleSwarm",
				Name:        "Swarm",
				Description: "No description",
				Enabled:     true,
				Rules: []*PolicyRule{
					{
						ID:            "RuleSwarm",
						Name:          "Swarm",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      PolicyRuleProtocolALL,
						Action:        PolicyTrafficActionAccept,
						Sources: []string{
							"GroupSwarm",
							"GroupAll",
						},
						Destinations: []string{
							"GroupSwarm",
						},
					},
				},
			},
		},
	}

	t.Run("check that all peers get map", func(t *testing.T) {
		for _, p := range account.Peers {
			peers, firewallRules := account.getPeerConnectionResources(p.ID)
			assert.GreaterOrEqual(t, len(peers), 2, "minimum number peers should present")
			assert.GreaterOrEqual(t, len(firewallRules), 2, "minimum number of firewall rules should present")
		}
	})

	t.Run("check first peer map details", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerB")
		assert.Len(t, peers, 7)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerE"])
		assert.Contains(t, peers, account.Peers["peerF"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "0.0.0.0",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "0.0.0.0",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerIP:    "100.65.32.206",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerIP:    "100.65.250.202",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.250.202",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerIP:    "100.65.13.186",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerIP:    "100.65.29.55",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(epectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})
}

func TestAccount_getPeersByPolicyDirect(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peerA": {
				ID:     "peerA",
				IP:     net.ParseIP("100.65.14.88"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerB": {
				ID:     "peerB",
				IP:     net.ParseIP("100.65.80.39"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerC": {
				ID:     "peerC",
				IP:     net.ParseIP("100.65.254.139"),
				Status: &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*Group{
			"GroupAll": {
				ID:   "GroupAll",
				Name: "All",
				Peers: []string{
					"peerB",
					"peerA",
					"peerC",
				},
			},
			"GroupSwarm": {
				ID:   "GroupSwarm",
				Name: "swarm",
				Peers: []string{
					"peerB",
				},
			},
			"peerF": {
				ID:   "peerF",
				Name: "dmz",
				Peers: []string{
					"peerC",
				},
			},
		},
		Policies: []*Policy{
			{
				ID:          "RuleDefault",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Enabled:     false,
				Rules: []*PolicyRule{
					{
						ID:            "RuleDefault",
						Name:          "Default",
						Description:   "This is a default rule that allows connections between all the resources",
						Bidirectional: true,
						Enabled:       false,
						Protocol:      PolicyRuleProtocolALL,
						Action:        PolicyTrafficActionAccept,
						Sources: []string{
							"GroupAll",
						},
						Destinations: []string{
							"GroupAll",
						},
					},
				},
			},
			{
				ID:          "RuleSwarm",
				Name:        "Swarm",
				Description: "No description",
				Enabled:     true,
				Rules: []*PolicyRule{
					{
						ID:            "RuleSwarm",
						Name:          "Swarm",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      PolicyRuleProtocolALL,
						Action:        PolicyTrafficActionAccept,
						Sources: []string{
							"GroupSwarm",
						},
						Destinations: []string{
							"peerF",
						},
					},
				},
			},
		},
	}

	t.Run("check first peer map", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerB")
		assert.Contains(t, peers, account.Peers["peerC"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(epectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})

	t.Run("check second peer map", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerC")
		assert.Contains(t, peers, account.Peers["peerB"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "100.65.80.39",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerIP:    "100.65.80.39",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(epectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})

	account.Policies[1].Rules[0].Bidirectional = false

	t.Run("check first peer map directional only", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerB")
		assert.Contains(t, peers, account.Peers["peerC"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(epectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})

	t.Run("check second peer map directional only", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerC")
		assert.Contains(t, peers, account.Peers["peerB"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "100.65.80.39",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(epectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})
}

func sortFunc() func(a *FirewallRule, b *FirewallRule) int {
	return func(a, b *FirewallRule) int {
		// Concatenate PeerIP and Direction as string for comparison
		aStr := a.PeerIP + fmt.Sprintf("%d", a.Direction)
		bStr := b.PeerIP + fmt.Sprintf("%d", b.Direction)

		// Compare the concatenated strings
		if aStr < bStr {
			return -1 // a is less than b
		}
		if aStr > bStr {
			return 1 // a is greater than b
		}
		return 0 // a is equal to b
	}
}
