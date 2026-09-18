package android

import (
	"sync"
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer"
)

func Test_routeOwners(t *testing.T) {
	router := peer.State{Mux: &sync.RWMutex{}, PubKey: "router"}
	router.SetRoutes(map[string]struct{}{"10.0.0.0/24": {}, "0.0.0.0/0": {}})
	other := peer.State{Mux: &sync.RWMutex{}, PubKey: "other"}
	other.SetRoutes(map[string]struct{}{"192.168.0.0/16": {}})
	idle := peer.State{Mux: &sync.RWMutex{}, PubKey: "idle"}

	owners := routeOwners([]peer.State{router, other, idle})

	if len(owners) != 3 {
		t.Fatalf("owners: %d, expected 3", len(owners))
	}
	for network, want := range map[string]string{
		"10.0.0.0/24":    "router",
		"0.0.0.0/0":      "router",
		"192.168.0.0/16": "other",
	} {
		if got := owners[network].PubKey; got != want {
			t.Errorf("owner of %s: %q, expected %q", network, got, want)
		}
	}
	if _, ok := owners["172.16.0.0/12"]; ok {
		t.Errorf("unexpected owner for a route nobody serves")
	}
}

func Test_routeOwners_FirstPeerWinsSharedRoute(t *testing.T) {
	first := peer.State{Mux: &sync.RWMutex{}, PubKey: "first"}
	first.SetRoutes(map[string]struct{}{"10.0.0.0/24": {}})
	second := peer.State{Mux: &sync.RWMutex{}, PubKey: "second"}
	second.SetRoutes(map[string]struct{}{"10.0.0.0/24": {}})

	owners := routeOwners([]peer.State{first, second})

	if got := owners["10.0.0.0/24"].PubKey; got != "first" {
		t.Errorf("owner: %q, expected first", got)
	}
}
