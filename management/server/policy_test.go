package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
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
		Groups: map[string]*nbgroup.Group{
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

	validatedPeers := make(map[string]struct{})
	for p := range account.Peers {
		validatedPeers[p] = struct{}{}
	}

	t.Run("check that all peers get map", func(t *testing.T) {
		for _, p := range account.Peers {
			peers, firewallRules := account.getPeerConnectionResources(context.Background(), p.ID, validatedPeers)
			assert.GreaterOrEqual(t, len(peers), 2, "minimum number peers should present")
			assert.GreaterOrEqual(t, len(firewallRules), 2, "minimum number of firewall rules should present")
		}
	})

	t.Run("check first peer map details", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerB", validatedPeers)
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
		Groups: map[string]*nbgroup.Group{
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

	approvedPeers := make(map[string]struct{})
	for p := range account.Peers {
		approvedPeers[p] = struct{}{}
	}

	t.Run("check first peer map", func(t *testing.T) {
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerB", approvedPeers)
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
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerC", approvedPeers)
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
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerB", approvedPeers)
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
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerC", approvedPeers)
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

func TestAccount_getPeersByPolicyPostureChecks(t *testing.T) {
	account := &Account{
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
		Groups: map[string]*nbgroup.Group{
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

	account.Policies = append(account.Policies, &Policy{
		ID:          "PolicyPostureChecks",
		Name:        "",
		Description: "This is the policy with posture checks applied",
		Enabled:     true,
		Rules: []*PolicyRule{
			{
				ID:      "RuleSwarm",
				Name:    "Swarm",
				Enabled: true,
				Action:  PolicyTrafficActionAccept,
				Destinations: []string{
					"GroupSwarm",
				},
				Sources: []string{
					"GroupAll",
				},
				Bidirectional: false,
				Protocol:      PolicyRuleProtocolTCP,
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
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerB", approvedPeers)
		assert.Len(t, peers, 4)
		assert.Len(t, firewallRules, 4)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerF"])

		// peerC satisfy the NB posture check, should establish connection to all destination group peer's
		// We expect a single permissive firewall rule which all outgoing connections
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerC", approvedPeers)
		assert.Len(t, peers, len(account.Groups["GroupSwarm"].Peers))
		assert.Len(t, firewallRules, 1)
		expectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "0.0.0.0",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
		}
		assert.ElementsMatch(t, firewallRules, expectedFirewallRules)

		// peerE doesn't fulfill the NB posture check and exists in only destination group Swarm,
		// all source group peers satisfying the NB posture check should establish connection
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerE", approvedPeers)
		assert.Len(t, peers, 4)
		assert.Len(t, firewallRules, 4)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerF"])

		// peerI doesn't fulfill the OS version posture check and exists in only destination group Swarm,
		// all source group peers satisfying the NB posture check should establish connection
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerI", approvedPeers)
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
		peers, firewallRules := account.getPeerConnectionResources(context.Background(), "peerB", approvedPeers)
		assert.Len(t, peers, 0)
		assert.Len(t, firewallRules, 0)

		// peerI doesn't satisfy the OS version posture check, and doesn't exist in destination group peer's
		// no connection should be established to any peer of destination group
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerI", approvedPeers)
		assert.Len(t, peers, 0)
		assert.Len(t, firewallRules, 0)

		// peerC satisfy the NB posture check, should establish connection to all destination group peer's
		// We expect a single permissive firewall rule which all outgoing connections
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerC", approvedPeers)
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
		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerE", approvedPeers)
		assert.Len(t, peers, 3)
		assert.Len(t, firewallRules, 3)
		assert.Contains(t, peers, account.Peers["peerA"])
		assert.Contains(t, peers, account.Peers["peerC"])
		assert.Contains(t, peers, account.Peers["peerD"])

		peers, firewallRules = account.getPeerConnectionResources(context.Background(), "peerA", approvedPeers)
		assert.Len(t, peers, 5)
		// assert peers from Group Swarm
		assert.Contains(t, peers, account.Peers["peerD"])
		assert.Contains(t, peers, account.Peers["peerE"])
		assert.Contains(t, peers, account.Peers["peerG"])
		assert.Contains(t, peers, account.Peers["peerH"])

		// assert peers from Group All
		assert.Contains(t, peers, account.Peers["peerC"])

		expectedFirewallRules := []*FirewallRule{
			{
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
			{
				PeerIP:    "100.65.32.206",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
			{
				PeerIP:    "100.65.13.186",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
			{
				PeerIP:    "100.65.29.55",
				Direction: firewallRuleDirectionOUT,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
			{
				PeerIP:    "100.65.254.139",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
			{
				PeerIP:    "100.65.62.5",
				Direction: firewallRuleDirectionIN,
				Action:    "accept",
				Protocol:  "tcp",
				Port:      "80",
			},
		}
		assert.Len(t, firewallRules, len(expectedFirewallRules))
		assert.ElementsMatch(t, firewallRules, expectedFirewallRules)
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

func TestPolicyAccountPeersUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroups(context.Background(), account.Id, userID, []*nbgroup.Group{
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
	})
	assert.NoError(t, err)

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Saving policy with rule groups with no peers should not update account's peers and not send peer update
	t.Run("saving policy with rule groups with no peers", func(t *testing.T) {
		policy := Policy{
			ID:      "policy-rule-groups-no-peers",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupB"},
					Destinations:  []string{"groupC"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
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
		policy := Policy{
			ID:      "policy-source-has-peers-destination-none",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupB"},
					Protocol:      PolicyRuleProtocolTCP,
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
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
		policy := Policy{
			ID:      "policy-destination-has-peers-source-none",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       false,
					Sources:       []string{"groupC"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Protocol:      PolicyRuleProtocolTCP,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
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
		policy := Policy{
			ID:      "policy-source-destination-peers",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
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
		policy := Policy{
			ID:      "policy-source-destination-peers",
			Enabled: false,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
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
		policy := Policy{
			ID:          "policy-source-destination-peers",
			Description: "updated description",
			Enabled:     false,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupA"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
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
		policy := Policy{
			ID:      "policy-source-destination-peers",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupD"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting policy should trigger account peers update and send peer update
	t.Run("deleting policy with source and destination groups with peers", func(t *testing.T) {
		policyID := "policy-source-destination-peers"

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyID, userID)
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
		policyID := "policy-destination-has-peers-source-none"
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting policy with no peers in groups should not update account's peers and not send peer update
	t.Run("deleting policy with no peers in groups", func(t *testing.T) {
		policyID := "policy-rule-groups-no-peers"
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePolicy(context.Background(), account.Id, policyID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

}
