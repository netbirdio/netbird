package server

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &Account{
		Peers: map[string]*Peer{
			"peerA": {
				ID: "peerA",
				IP: net.ParseIP("100.65.14.88"),
			},
			"peerB": {
				ID: "peerB",
				IP: net.ParseIP("100.65.80.39"),
			},
			"peerC": {
				ID: "peerC",
				IP: net.ParseIP("100.65.254.139"),
			},
			"peerD": {
				ID: "peerD",
				IP: net.ParseIP("100.65.62.5"),
			},
			"peerE": {
				ID: "peerE",
				IP: net.ParseIP("100.65.32.206"),
			},
			"peerF": {
				ID: "peerF",
				IP: net.ParseIP("100.65.250.202"),
			},
			"peerG": {
				ID: "peerG",
				IP: net.ParseIP("100.65.13.186"),
			},
			"peerH": {
				ID: "peerH",
				IP: net.ParseIP("100.65.29.55"),
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
		Rules: map[string]*Rule{
			"RuleDefault": {
				ID:          "RuleDefault",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Source: []string{
					"GroupAll",
				},
				Destination: []string{
					"GroupAll",
				},
			},
			"RuleSwarm": {
				ID:          "RuleSwarm",
				Name:        "Swarm",
				Description: "",
				Source: []string{
					"GroupSwarm",
					"GroupAll",
				},
				Destination: []string{
					"GroupSwarm",
				},
			},
		},
	}

	rule1, err := RuleToPolicy(account.Rules["RuleDefault"])
	assert.NoError(t, err)

	rule2, err := RuleToPolicy(account.Rules["RuleSwarm"])
	assert.NoError(t, err)

	account.Policies = append(account.Policies, rule1, rule2)

	t.Run("check that all peers get map", func(t *testing.T) {
		for _, p := range account.Peers {
			peers, firewallRules := account.getPeerConnectionResources(p.ID)
			assert.GreaterOrEqual(t, len(peers), 2, "mininum number peers should present")
			assert.GreaterOrEqual(t, len(firewallRules), 2, "mininum number of firewall rules should present")
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
				PeerID:    "peerA",
				PeerIP:    "100.65.14.88",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerA",
				PeerIP:    "100.65.14.88",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerC",
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerC",
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerID:    "peerD",
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerD",
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerID:    "peerE",
				PeerIP:    "100.65.32.206",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerE",
				PeerIP:    "100.65.32.206",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerID:    "peerF",
				PeerIP:    "100.65.250.202",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerF",
				PeerIP:    "100.65.250.202",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerID:    "peerG",
				PeerIP:    "100.65.13.186",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerG",
				PeerIP:    "100.65.13.186",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},

			{
				PeerID:    "peerH",
				PeerIP:    "100.65.29.55",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerH",
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
		Peers: map[string]*Peer{
			"peerA": {
				ID: "peerA",
				IP: net.ParseIP("100.65.14.88"),
			},
			"peerB": {
				ID: "peerB",
				IP: net.ParseIP("100.65.80.39"),
			},
			"peerC": {
				ID: "peerC",
				IP: net.ParseIP("100.65.254.139"),
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
		Rules: map[string]*Rule{
			"RuleDefault": {
				ID:          "RuleDefault",
				Name:        "Default",
				Disabled:    true,
				Description: "This is a default rule that allows connections between all the resources",
				Source: []string{
					"GroupAll",
				},
				Destination: []string{
					"GroupAll",
				},
			},
			"RuleSwarm": {
				ID:          "RuleSwarm",
				Name:        "Swarm",
				Description: "",
				Source: []string{
					"GroupSwarm",
				},
				Destination: []string{
					"peerF",
				},
			},
		},
	}

	rule1, err := RuleToPolicy(account.Rules["RuleDefault"])
	assert.NoError(t, err)

	rule2, err := RuleToPolicy(account.Rules["RuleSwarm"])
	assert.NoError(t, err)

	account.Policies = append(account.Policies, rule1, rule2)

	t.Run("check first peer map", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources("peerB")
		assert.Contains(t, peers, account.Peers["peerC"])

		epectedFirewallRules := []*FirewallRule{
			{
				PeerID:    "peerC",
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerC",
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
				PeerID:    "peerB",
				PeerIP:    "100.65.80.39",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
			},
			{
				PeerID:    "peerB",
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
				PeerID:    "peerC",
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
				PeerID:    "peerB",
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

func sortFunc() func(a *FirewallRule, b *FirewallRule) bool {
	return func(a, b *FirewallRule) bool {
		return a.PeerID+fmt.Sprintf("%d", a.Direction) < b.PeerID+fmt.Sprintf("%d", b.Direction)
	}
}
