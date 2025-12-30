package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &types.Account{
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
				Meta:   nbpeer.PeerSystemMeta{WtVersion: "0.48.0"},
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
			"peerI": {
				ID:     "peerI",
				IP:     net.ParseIP("100.65.31.2"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerK": {
				ID:     "peerK",
				IP:     net.ParseIP("100.32.80.1"),
				Status: &nbpeer.PeerStatus{},
				Meta:   nbpeer.PeerSystemMeta{WtVersion: "0.30.0"},
			},
		},
		Groups: map[string]*types.Group{
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
			"GroupWorkstations": {
				ID:   "GroupWorkstations",
				Name: "GroupWorkstations",
				Peers: []string{
					"peerB",
					"peerA",
					"peerD",
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
			"GroupDMZ": {
				ID:   "GroupDMZ",
				Name: "dmz",
				Peers: []string{
					"peerI",
				},
			},
			"GroupWorkflow": {
				ID:   "GroupWorkflow",
				Name: "workflow",
				Peers: []string{
					"peerK",
				},
			},
		},
		Policies: []*types.Policy{
			{
				ID:          "RuleDefault",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Enabled:     true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleDefault",
						Name:          "Default",
						Description:   "This is a default rule that allows connections between all the resources",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
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
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleSwarm",
						Name:          "Swarm",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
						Sources: []string{
							"GroupSwarm",
							"GroupWorkstations",
						},
						Destinations: []string{
							"GroupSwarm",
						},
					},
				},
			},
			{
				ID:          "RuleDMZ",
				Name:        "Dmz",
				Description: "No description",
				Enabled:     true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleDMZ",
						Name:          "Dmz",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						PortRanges: []types.RulePortRange{
							{
								Start: 8080,
								End:   8083,
							},
						},
						Sources: []string{
							"GroupWorkstations",
						},
						Destinations: []string{
							"GroupDMZ",
						},
					},
				},
			},
			{
				ID:          "RuleWorkflow",
				Name:        "Workflow",
				Description: "No description",
				Enabled:     true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleWorkflow",
						Name:          "Workflow",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						PortRanges: []types.RulePortRange{
							{
								Start: 8088,
								End:   8088,
							},
							{
								Start: 9090,
								End:   9095,
							},
						},
						Sources: []string{
							"GroupWorkflow",
						},
						Destinations: []string{
							"GroupDMZ",
						},
					},
				},
			},
		},
	}

	validatedPeers := make(map[string]struct{})
	for p := range account.Peers {
		validatedPeers[p] = struct{}{}
	}

	t.Run("check that all peers get map", func(t *testing.T) {
		for _, p := range account.Peers {
			peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), p, validatedPeers, account.GetActiveGroupUsers())
			assert.GreaterOrEqual(t, len(peers), 1, "minimum number peers should present")
			assert.GreaterOrEqual(t, len(firewallRules), 1, "minimum number of firewall rules should present")
		}
	})

	t.Run("check first peer map details", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerB"], validatedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 8)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerE"])
		assert.Contains(t, peers, account.Peers["peerF"])
		assert.Contains(t, peers, account.Peers["peerG"])
		assert.Contains(t, peers, account.Peers["peerH"])
		assert.Contains(t, peers, account.Peers["peerI"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.14.88",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.250.202",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.250.202",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleDefault",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},

			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},

			{
				PeerIP:    "100.65.250.202",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.250.202",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},

			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},

			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.31.2",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				PortRange: types.RulePortRange{Start: 8080, End: 8083},
				PolicyID:  "RuleDMZ",
			},
			{
				PeerIP:    "100.65.31.2",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				PortRange: types.RulePortRange{Start: 8080, End: 8083},
				PolicyID:  "RuleDMZ",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))

		for _, rule := range firewallRules {
			contains := false
			for _, expectedRule := range expectedFirewallRules {
				if rule.Equal(expectedRule) {
					contains = true
					break
				}
			}
			assert.True(t, contains, "rule not found in expected rules %#v", rule)
		}
	})

	t.Run("check port ranges support for older peers", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerK"], validatedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 1)
		assert.Contains(t, peers, account.Peers["peerI"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.31.2",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "8088",
				PolicyID:  "RuleWorkflow",
			},
			{
				PeerIP:    "100.65.31.2",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "8088",
				PolicyID:  "RuleWorkflow",
			},
		}
		assert.ElementsMatch(t, firewallRules, expectedFirewallRules)
	})
}

func TestAccount_getPeersByPolicyDirect(t *testing.T) {
	account := &types.Account{
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
		Groups: map[string]*types.Group{
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
		Policies: []*types.Policy{
			{
				ID:          "RuleDefault",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Enabled:     false,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleDefault",
						Name:          "Default",
						Description:   "This is a default rule that allows connections between all the resources",
						Bidirectional: true,
						Enabled:       false,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
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
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleSwarm",
						Name:          "Swarm",
						Description:   "No description",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
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

	approvedPeers := make(map[string]struct{})
	for p := range account.Peers {
		approvedPeers[p] = struct{}{}
	}

	t.Run("check first peer map", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerB"], approvedPeers, account.GetActiveGroupUsers())
		assert.Contains(t, peers, account.Peers["peerC"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		slices.SortFunc(expectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, expectedFirewallRules[i], firewallRules[i])
		}
	})

	t.Run("check second peer map", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerC"], approvedPeers, account.GetActiveGroupUsers())
		assert.Contains(t, peers, account.Peers["peerB"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.80.39",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.80.39",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		slices.SortFunc(expectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, expectedFirewallRules[i], firewallRules[i])
		}
	})

	account.Policies[1].Rules[0].Bidirectional = false

	t.Run("check first peer map directional only", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerB"], approvedPeers, account.GetActiveGroupUsers())
		assert.Contains(t, peers, account.Peers["peerC"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		slices.SortFunc(expectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, expectedFirewallRules[i], firewallRules[i])
		}
	})

	t.Run("check second peer map directional only", func(t *testing.T) {
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerC"], approvedPeers, account.GetActiveGroupUsers())
		assert.Contains(t, peers, account.Peers["peerB"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.80.39",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "all",
				Port:      "",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		slices.SortFunc(expectedFirewallRules, sortFunc())
		slices.SortFunc(firewallRules, sortFunc())
		for i := range firewallRules {
			assert.Equal(t, expectedFirewallRules[i], firewallRules[i])
		}
	})
}

func TestAccount_getPeersByPolicyPostureChecks(t *testing.T) {
	account := &types.Account{
		Peers: map[string]*nbpeer.Peer{
			"peerA": {
				ID:     "peerA",
				IP:     net.ParseIP("100.65.14.88"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.7",
					WtVersion:     "0.25.9",
				},
			},
			"peerB": {
				ID:     "peerB",
				IP:     net.ParseIP("100.65.80.39"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.23.0",
				},
			},
			"peerC": {
				ID:     "peerC",
				IP:     net.ParseIP("100.65.254.139"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.25.8",
				},
			},
			"peerD": {
				ID:     "peerD",
				IP:     net.ParseIP("100.65.62.5"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.0",
					WtVersion:     "0.25.9",
				},
			},
			"peerE": {
				ID:     "peerE",
				IP:     net.ParseIP("100.65.32.206"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.24.0",
				},
			},
			"peerF": {
				ID:     "peerF",
				IP:     net.ParseIP("100.65.250.202"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.25.9",
				},
			},
			"peerG": {
				ID:     "peerG",
				IP:     net.ParseIP("100.65.13.186"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.23.2",
				},
			},
			"peerH": {
				ID:     "peerH",
				IP:     net.ParseIP("100.65.29.55"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.6.1",
					WtVersion:     "0.23.1",
				},
			},
			"peerI": {
				ID:     "peerI",
				IP:     net.ParseIP("100.65.21.56"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "windows",
					KernelVersion: "10.0.14393.2430",
					WtVersion:     "0.25.1",
				},
			},
		},
		Groups: map[string]*types.Group{
			"GroupAll": {
				ID:   "GroupAll",
				Name: "All",
				Peers: []string{
					"peerB",
					"peerA",
					"peerD",
					"peerC",
					"peerF",
					"peerG",
					"peerH",
					"peerI",
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
					"peerI",
				},
			},
		},
		PostureChecks: []*posture.Checks{
			{
				ID:          "PostureChecksDefault",
				Name:        "Default",
				Description: "This is a posture checks that check if peer is running required versions",
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{
						MinVersion: "0.25",
					},
					OSVersionCheck: &posture.OSVersionCheck{
						Linux: &posture.MinKernelVersionCheck{
							MinKernelVersion: "6.6.0",
						},
					},
				},
			},
		},
	}

	account.Policies = append(account.Policies, &types.Policy{
		ID:          "PolicyPostureChecks",
		Name:        "",
		Description: "This is the policy with posture checks applied",
		Enabled:     true,
		Rules: []*types.PolicyRule{
			{
				ID:      "RuleSwarm",
				Name:    "Swarm",
				Enabled: true,
				Action:  types.PolicyTrafficActionAccept,
				Destinations: []string{
					"GroupSwarm",
				},
				Sources: []string{
					"GroupAll",
				},
				Bidirectional: false,
				Protocol:      types.PolicyRuleProtocolTCP,
				Ports:         []string{"80"},
			},
		},
		SourcePostureChecks: []string{
			"PostureChecksDefault",
		},
	})

	approvedPeers := make(map[string]struct{})
	for p := range account.Peers {
		approvedPeers[p] = struct{}{}
	}
	t.Run("verify peer's network map with default group peer list", func(t *testing.T) {
		// peerB doesn't fulfill the NB posture check but is included in the destination group Swarm,
		// will establish a connection with all source peers satisfying the NB posture check.
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerB"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 4)
		assert.Len(t, firewallRules, 4)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerF"])

		// peerC satisfy the NB posture check, should establish connection to all destination group peer's
		// We expect a single permissive firewall rule which all outgoing connections
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerC"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, len(account.Groups["GroupSwarm"].Peers))
		assert.Len(t, firewallRules, 7)
		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.80.39",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.14.88",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.21.56",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.ElementsMatch(t, firewallRules, expectedFirewallRules)

		// peerE doesn't fulfill the NB posture check and exists in only destination group Swarm,
		// all source group peers satisfying the NB posture check should establish connection
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerE"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 4)
		assert.Len(t, firewallRules, 4)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerF"])

		// peerI doesn't fulfill the OS version posture check and exists in only destination group Swarm,
		// all source group peers satisfying the NB posture check should establish connection
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerI"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 4)
		assert.Len(t, firewallRules, 4)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerF"])
	})

	t.Run("verify peer's network map with modified group peer list", func(t *testing.T) {
		//  Removing peerB as the part of destination group Swarm
		account.Groups["GroupSwarm"].Peers = []string{"peerA", "peerD", "peerE", "peerG", "peerH"}

		// peerB doesn't satisfy the NB posture check, and doesn't exist in destination group peer's
		// no connection should be established to any peer of destination group
		peers, firewallRules, _, _ := account.GetPeerConnectionResources(context.Background(), account.Peers["peerB"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 0)
		assert.Len(t, firewallRules, 0)

		// peerI doesn't satisfy the OS version posture check, and doesn't exist in destination group peer's
		// no connection should be established to any peer of destination group
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerI"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 0)
		assert.Len(t, firewallRules, 0)

		// peerC satisfy the NB posture check, should establish connection to all destination group peer's
		// We expect a single permissive firewall rule which all outgoing connections
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerC"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, len(account.Groups["GroupSwarm"].Peers))
		assert.Len(t, firewallRules, len(account.Groups["GroupSwarm"].Peers))

		peerIDs := make([]string, 0, len(peers))
		for _, peer := range peers {
			peerIDs = append(peerIDs, peer.ID)
		}
		assert.ElementsMatch(t, peerIDs, account.Groups["GroupSwarm"].Peers)

		// Removing peerF as the part of source group All
		account.Groups["GroupAll"].Peers = []string{"peerB", "peerA", "peerD", "peerC", "peerG", "peerH"}

		// peerE doesn't fulfill the NB posture check and exists in only destination group Swarm,
		// all source group peers satisfying the NB posture check should establish connection
		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerE"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 3)
		assert.Len(t, firewallRules, 3)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])

		peers, firewallRules, _, _ = account.GetPeerConnectionResources(context.Background(), account.Peers["peerA"], approvedPeers, account.GetActiveGroupUsers())
		assert.Len(t, peers, 5)
		// assert peers from Group Swarm
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerE"])
		assert.Contains(t, peers, account.Peers["peerG"])
		assert.Contains(t, peers, account.Peers["peerH"])

		// assert peers from Group All
		assert.Contains(t, peers, account.Peers["peerC"])

		expectedFirewallRules := []*types.FirewallRule{
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: types.FirewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: types.FirewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
				PolicyID:  "RuleSwarm",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		assert.ElementsMatch(t, firewallRules, expectedFirewallRules)
	})
}

func sortFunc() func(a *types.FirewallRule, b *types.FirewallRule) int {
	return func(a, b *types.FirewallRule) int {
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

func TestPolicyAccountPeersUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	g := []*types.Group{
		{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{peer1.ID, peer3.ID},
		},
		{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{},
		},
		{
			ID:    "groupC",
			Name:  "GroupC",
			Peers: []string{},
		},
		{
			ID:    "groupD",
			Name:  "GroupD",
			Peers: []string{peer1.ID, peer2.ID},
		},
	}
	for _, group := range g {
		err := manager.CreateGroup(context.Background(), account.Id, userID, group)
		assert.NoError(t, err)
	}

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	var policyWithGroupRulesNoPeers *types.Policy
	var policyWithDestinationPeersOnly *types.Policy
	var policyWithSourceAndDestinationPeers *types.Policy
	var err error

	// Saving policy with rule groups with no peers should not update account's peers and not send peer update
	t.Run("saving policy with rule groups with no peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithGroupRulesNoPeers, err = manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupB"},
					Destinations:  []string{"groupC"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Saving policy with source group containing peers, but destination group without peers should
	// update account's peers and send peer update
	t.Run("saving policy where source has peers but destination does not", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupB"},
					Protocol:      types.PolicyRuleProtocolTCP,
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Saving policy with destination group containing peers, but source group without peers should
	// update account's peers and send peer update
	t.Run("saving policy where destination has peers but source does not", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithDestinationPeersOnly, err = manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupC"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolTCP,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Saving policy with destination and source groups containing peers should update account's peers
	// and send peer update
	t.Run("saving policy with source and destination groups with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithSourceAndDestinationPeers, err = manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Disabling policy with destination and source groups containing peers should update account's peers
	// and send peer update
	t.Run("disabling policy with source and destination groups with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithSourceAndDestinationPeers.Enabled = false
		policyWithSourceAndDestinationPeers, err = manager.SavePolicy(context.Background(), account.Id, userID, policyWithSourceAndDestinationPeers, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Updating disabled policy with destination and source groups containing peers should not update account's peers
	// or send peer update
	t.Run("updating disabled policy with source and destination groups with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithSourceAndDestinationPeers.Description = "updated description"
		policyWithSourceAndDestinationPeers.Rules[0].Destinations = []string{"groupA"}
		policyWithSourceAndDestinationPeers, err = manager.SavePolicy(context.Background(), account.Id, userID, policyWithSourceAndDestinationPeers, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Enabling policy with destination and source groups containing peers should update account's peers
	// and send peer update
	t.Run("enabling policy with source and destination groups with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		policyWithSourceAndDestinationPeers.Enabled = true
		policyWithSourceAndDestinationPeers, err = manager.SavePolicy(context.Background(), account.Id, userID, policyWithSourceAndDestinationPeers, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting policy should trigger account peers update and send peer update
	t.Run("deleting policy with source and destination groups with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyWithSourceAndDestinationPeers.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}

	})

	// Deleting policy with destination group containing peers, but source group without peers should
	// update account's peers and send peer update
	t.Run("deleting policy where destination has peers but source does not", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyWithDestinationPeersOnly.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting policy with no peers in groups should not update account's peers and not send peer update
	t.Run("deleting policy with no peers in groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyWithGroupRulesNoPeers.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

}
