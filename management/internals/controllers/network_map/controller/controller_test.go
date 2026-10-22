package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestComputeForwarderPort(t *testing.T) {
	// Test with empty peers list
	peers := []*nbpeer.Peer{}
	result := computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for empty peers list, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have old versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.26.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with old versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have new versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.DnsForwarderPort) {
		t.Errorf("Expected %d for peers with new versions, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have mixed versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with mixed versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have empty version
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with empty version, got %d", network_map.OldForwarderPort, result)
	}

	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "development",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result == int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with dev version, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have unknown version string
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "unknown",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with unknown version, got %d", network_map.OldForwarderPort, result)
	}
}

func TestGetValidatedPeerWithComponents_DeletedPeer(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockrequestBuffer := account.NewMockRequestBuffer(ctrl)

	c := Controller{
		requestBuffer: mockrequestBuffer,
	}

	mockrequestBuffer.EXPECT().GetAccountWithBackpressure(gomock.Any(), gomock.Any()).Return(&types.Account{}, nil)
	peer, components, posturechecks, dnsforwardPort, err := c.GetValidatedPeerWithComponents(context.TODO(), false, "test-account-id", &nbpeer.Peer{ID: "test-peer-id"})

	assert.Nil(t, peer)
	assert.Nil(t, components)
	assert.Nil(t, posturechecks)
	assert.Equal(t, int64(0), dnsforwardPort)
	assert.NotNil(t, err)
}

func TestMergePeerSelections(t *testing.T) {
	t.Run("ids are unioned", func(t *testing.T) {
		merged := mergePeerSelections(selectedPeers("peer-1", "peer-2"), selectedPeers("peer-2", "peer-3"))

		assert.False(t, merged.all)
		assert.Equal(t, map[string]struct{}{"peer-1": {}, "peer-2": {}, "peer-3": {}}, merged.peerIDs)
	})

	t.Run("all wins on either side", func(t *testing.T) {
		assert.True(t, mergePeerSelections(allPeers(), selectedPeers("peer-1")).all)
		assert.True(t, mergePeerSelections(selectedPeers("peer-1"), allPeers()).all)
	})
}

func TestSelectPeers(t *testing.T) {
	data := func(rules ...*nmdata.PolicyRule) *networkmap.NetworkMapData {
		nmd := &networkmap.NetworkMapData{
			Peers:  map[string]*nmdata.Peer{},
			Groups: map[string]*nmdata.Group{},
		}
		all := &nmdata.Group{ID: "group-all", Name: "All"}
		for i := range 10 {
			id := fmt.Sprintf("peer-%d", i)
			nmd.Peers[id] = &nmdata.Peer{ID: id}
			all.Peers = append(all.Peers, id)
		}
		nmd.Groups[all.ID] = all
		nmd.Groups["group-a"] = &nmdata.Group{ID: "group-a", Peers: []string{"peer-1", "peer-2"}}
		nmd.Groups["group-b"] = &nmdata.Group{ID: "group-b", Peers: []string{"peer-3"}}
		nmd.Policies = []*nmdata.Policy{{ID: "policy", Enabled: true, Rules: rules}}
		return nmd
	}
	rule := func(protocol string, sources, destinations string) *nmdata.PolicyRule {
		return &nmdata.PolicyRule{Enabled: true, Protocol: protocol, Ports: []string{"443"}, Sources: []string{sources}, Destinations: []string{destinations}}
	}

	t.Run("a closure below half the account is read alone, without users", func(t *testing.T) {
		selection := SelectPeers(data(rule("tcp", "group-a", "group-b")), []string{"peer-1"})

		assert.False(t, selection.AllPeers)
		assert.ElementsMatch(t, []string{"peer-1", "peer-3"}, selection.PeerIDs)
		assert.True(t, selection.SkipUsers)
	})

	t.Run("a closure reaching half the account reads every peer", func(t *testing.T) {
		selection := SelectPeers(data(rule("tcp", "group-all", "group-all")), []string{"peer-1"})

		assert.True(t, selection.AllPeers)
		assert.Empty(t, selection.PeerIDs)
	})

	t.Run("a netbird ssh rule reads the users", func(t *testing.T) {
		selection := SelectPeers(data(rule(string(types.PolicyRuleProtocolNetbirdSSH), "group-a", "group-b")), []string{"peer-1"})

		assert.False(t, selection.SkipUsers)
	})
}
