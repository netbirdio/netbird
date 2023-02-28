package server

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &Account{
		Peers: map[string]*Peer{
			"peer1": {
				ID: "peer1",
				IP: net.IPv4(10, 20, 0, 1),
			},
			"peer2": {
				ID: "peer2",
				IP: net.IPv4(10, 20, 0, 2),
			},
			"peer3": {
				ID: "peer3",
				IP: net.IPv4(10, 20, 0, 3),
			},
		},
		Groups: map[string]*Group{
			"gid1": {
				ID:    "gid1",
				Name:  "all",
				Peers: []string{"peer1", "peer2", "peer3"},
			},
		},
		Policies: []*Policy{
			{
				ID:          "default",
				Name:        "default",
				Description: "default",
				Disabled:    false,
				Query:       fmt.Sprintf(defaultPolicy, `"gid1"`, `"gid1"`),
			},
		},
	}

	peers, firewallRules := account.getPeersByPolicy("peer1")
	expected := []*Peer{account.Peers["peer2"], account.Peers["peer3"]}
	assert.Equal(t, peers, expected)

	epectedFirewallRules := []*FirewallRule{
		{PeerID: "peer2", PeerIP: "10.20.0.2", Direction: "dst", Action: "accept", Port: ""},
		{PeerID: "peer3", PeerIP: "10.20.0.3", Direction: "dst", Action: "accept", Port: ""},
		{PeerID: "peer2", PeerIP: "10.20.0.2", Direction: "src", Action: "accept", Port: ""},
		{PeerID: "peer3", PeerIP: "10.20.0.3", Direction: "src", Action: "accept", Port: ""},
	}
	assert.Len(t, firewallRules, len(epectedFirewallRules))
	for i := range firewallRules {
		assert.Equal(t, firewallRules[i], epectedFirewallRules[i])
	}
}
