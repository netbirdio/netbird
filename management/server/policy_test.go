package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &Account{
		Peers: map[string]*Peer{
			"cfif97at2r9s73au3q00": {
				ID: "cfif97at2r9s73au3q00",
				IP: net.ParseIP("100.65.14.88"),
			},
			"cfif97at2r9s73au3q0g": {
				ID: "cfif97at2r9s73au3q0g",
				IP: net.ParseIP("100.65.80.39"),
			},
			"cfif97at2r9s73au3q10": {
				ID: "cfif97at2r9s73au3q10",
				IP: net.ParseIP("100.65.254.139"),
			},
			"cfif97at2r9s73au3q20": {
				ID: "cfif97at2r9s73au3q20",
				IP: net.ParseIP("100.65.62.5"),
			},
			"cfj4tiqt2r9s73dmeun0": {
				ID: "cfj4tiqt2r9s73dmeun0",
				IP: net.ParseIP("100.65.32.206"),
			},
			"cg7h032t2r9s73cg5fk0": {
				ID: "cg7h032t2r9s73cg5fk0",
				IP: net.ParseIP("100.65.250.202"),
			},
			"cgcnkj2t2r9s73cg5vv0": {
				ID: "cgcnkj2t2r9s73cg5vv0",
				IP: net.ParseIP("100.65.13.186"),
			},
			"cgcol4qt2r9s73cg601g": {
				ID: "cgcol4qt2r9s73cg601g",
				IP: net.ParseIP("100.65.29.55"),
			},
		},
		Groups: map[string]*Group{
			"cet9e92t2r9s7383ns20": {
				ID:   "cet9e92t2r9s7383ns20",
				Name: "All",
				Peers: []string{
					"cfif97at2r9s73au3q0g",
					"cfif97at2r9s73au3q00",
					"cfif97at2r9s73au3q20",
					"cfif97at2r9s73au3q10",
					"cfj4tiqt2r9s73dmeun0",
					"cg7h032t2r9s73cg5fk0",
					"cgcnkj2t2r9s73cg5vv0",
					"cgcol4qt2r9s73cg601g",
				},
			},
			"cev90bat2r9s7383o150": {
				ID:   "cev90bat2r9s7383o150",
				Name: "swarm",
				Peers: []string{
					"cfif97at2r9s73au3q0g",
					"cfif97at2r9s73au3q00",
					"cfif97at2r9s73au3q20",
					"cfj4tiqt2r9s73dmeun0",
					"cgcnkj2t2r9s73cg5vv0",
					"cgcol4qt2r9s73cg601g",
				},
			},
		},
		Rules: map[string]*Rule{
			"cet9e92t2r9s7383ns2g": {
				ID:          "cet9e92t2r9s7383ns2g",
				Name:        "Default",
				Description: "This is a default rule that allows connections between all the resources",
				Source: []string{
					"cet9e92t2r9s7383ns20",
				},
				Destination: []string{
					"cet9e92t2r9s7383ns20",
				},
			},
			"cev90bat2r9s7383o15g": {
				ID:          "cev90bat2r9s7383o15g",
				Name:        "Swarm",
				Description: "",
				Source: []string{
					"cev90bat2r9s7383o150",
					"cet9e92t2r9s7383ns20",
				},
				Destination: []string{
					"cev90bat2r9s7383o150",
				},
			},
		},
	}

	rule1, err := RuleToPolicy(account.Rules["cet9e92t2r9s7383ns2g"])
	assert.NoError(t, err)

	rule2, err := RuleToPolicy(account.Rules["cev90bat2r9s7383o15g"])
	assert.NoError(t, err)

	account.Policies = append(account.Policies, rule1, rule2)

	t.Run("check that all peers get map", func(t *testing.T) {
		for _, p := range account.Peers {
			peers, firewallRules := account.getPeersByPolicy(p.ID)
			assert.GreaterOrEqual(t, len(peers), 2, "mininum number peers should present")
			assert.GreaterOrEqual(t, len(firewallRules), 2, "mininum number of firewall rules should present")
		}
	})

	t.Run("check first peer map details", func(t *testing.T) {
		peers, firewallRules := account.getPeersByPolicy("cfif97at2r9s73au3q0g")
		assert.Len(t, peers, 7)
		assert.Contains(t, peers, account.Peers["cfif97at2r9s73au3q00"])
		assert.Contains(t, peers, account.Peers["cfif97at2r9s73au3q10"])
		assert.Contains(t, peers, account.Peers["cfif97at2r9s73au3q20"])
		assert.Contains(t, peers, account.Peers["cfj4tiqt2r9s73dmeun0"])
		assert.Contains(t, peers, account.Peers["cg7h032t2r9s73cg5fk0"])

		epectedFirewallRules := []*FirewallRule{
			{PeerID: "cfif97at2r9s73au3q00", PeerIP: "100.65.14.88", Direction: "src", Action: "accept", Port: "", id: "3d3ab1116cfc02ae999e552649a73617"},
			{PeerID: "cfif97at2r9s73au3q00", PeerIP: "100.65.14.88", Direction: "dst", Action: "accept", Port: "", id: "df1afc66491e91943f1382bf0bd2e4fd"},

			{PeerID: "cfif97at2r9s73au3q0g", PeerIP: "100.65.80.39", Direction: "dst", Action: "accept", Port: "", id: "b54a41e130683748785ac97a72aa4ff2"},
			{PeerID: "cfif97at2r9s73au3q0g", PeerIP: "100.65.80.39", Direction: "src", Action: "accept", Port: "", id: "b75ac1cc640a38568edaaf8b02d7d735"},

			{PeerID: "cfif97at2r9s73au3q10", PeerIP: "100.65.254.139", Direction: "dst", Action: "accept", Port: "", id: "9f763e9d3d9ba9ecbe39fcb002342c70"},
			{PeerID: "cfif97at2r9s73au3q10", PeerIP: "100.65.254.139", Direction: "src", Action: "accept", Port: "", id: "5f3943af0064efc7bd190b85616aa861"},

			{PeerID: "cfif97at2r9s73au3q20", PeerIP: "100.65.62.5", Direction: "dst", Action: "accept", Port: "", id: "43f5e028d2b1b688d34e61e122c35da8"},
			{PeerID: "cfif97at2r9s73au3q20", PeerIP: "100.65.62.5", Direction: "src", Action: "accept", Port: "", id: "ff350f35f0fc509ff3abba0d36d246b0"},

			{PeerID: "cfj4tiqt2r9s73dmeun0", PeerIP: "100.65.32.206", Direction: "dst", Action: "accept", Port: "", id: "bb322ec68406f509d4edc784166bfa13"},
			{PeerID: "cfj4tiqt2r9s73dmeun0", PeerIP: "100.65.32.206", Direction: "src", Action: "accept", Port: "", id: "440fbeab66661cff33f7f7b873506e8f"},

			{PeerID: "cg7h032t2r9s73cg5fk0", PeerIP: "100.65.250.202", Direction: "dst", Action: "accept", Port: "", id: "66b7aa90e683e011772608b58cfd57fa"},
			{PeerID: "cg7h032t2r9s73cg5fk0", PeerIP: "100.65.250.202", Direction: "src", Action: "accept", Port: "", id: "0375ba033e0911f549b1828a57220099"},

			{PeerID: "cgcnkj2t2r9s73cg5vv0", PeerIP: "100.65.13.186", Direction: "dst", Action: "accept", Port: "", id: "5941f150bd7815b9c426143c120946d0"},
			{PeerID: "cgcnkj2t2r9s73cg5vv0", PeerIP: "100.65.13.186", Direction: "src", Action: "accept", Port: "", id: "1021a5a55157b6473b2617e5f6b37f6f"},

			{PeerID: "cgcol4qt2r9s73cg601g", PeerIP: "100.65.29.55", Direction: "dst", Action: "accept", Port: "", id: "87b216d3ac8bcd4f4731b288c4e09765"},
			{PeerID: "cgcol4qt2r9s73cg601g", PeerIP: "100.65.29.55", Direction: "src", Action: "accept", Port: "", id: "0bddf2588a5086a18bbd0ddee61cc590"},
		}
		assert.Len(t, firewallRules, len(epectedFirewallRules))
		slices.SortFunc(firewallRules, func(a, b *FirewallRule) bool {
			return a.PeerID < b.PeerID
		})
		for i := range firewallRules {
			assert.Equal(t, epectedFirewallRules[i], firewallRules[i])
		}
	})
}
