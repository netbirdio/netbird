package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccount_getPeersByPolicy(t *testing.T) {
	account := &Account{
		Peers: map[string]*Peer{
			"peer1": {
				ID: "peer1",
			},
			"peer2": {
				ID: "peer2",
			},
			"peer3": {
				ID: "peer3",
			},
		},
		Groups: map[string]*Group{
			"default": {
				ID:    "default",
				Name:  "all",
				Peers: []string{"peer1", "peer2", "peer3"},
			},
		},
		Rules: map[string]*Rule{
			"default": {
				ID:          "default",
				Name:        "default",
				Description: "All to All",
				Source:      []string{"all"},
				Destination: []string{"all"},
				Flow:        TrafficFlowBidirect,
			},
		},
	}

	peers := account.getPeersByPolicy("peer1")
	expected := []*Peer{account.Peers["peer2"], account.Peers["peer3"]}
	assert.Equal(t, peers, expected)
}
