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

func TestClosureLimit(t *testing.T) {
	data := func(groupSizes ...int) *networkmap.NetworkMapData {
		nmd := &networkmap.NetworkMapData{Groups: map[string]*nmdata.Group{}}
		for i, size := range groupSizes {
			id := fmt.Sprintf("group-%d", i)
			nmd.Groups[id] = &nmdata.Group{ID: id, Peers: make([]string, size)}
		}
		return nmd
	}

	assert.Equal(t, 50, closureLimit(data(100, 30, 7)), "half of the largest group")
	assert.Equal(t, 1, closureLimit(data(1)), "never below one")
	assert.Equal(t, 1, closureLimit(data()), "an account without groups")
}
