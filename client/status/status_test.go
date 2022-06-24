package status

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAddPeer(t *testing.T) {
	key := "abc"
	status := NewStatus()
	err := status.AddPeer(PeerState{
		PubKey: key,
	})
	assert.NoError(t, err, "shouldn't return error")

	state, exists := status.Peers[key]
	assert.True(t, exists, "value was found")
	assert.Equal(t, key, state.PubKey, "key should be equal")
}

func TestUpdatePeerStatus(t *testing.T) {
	key := "abc"
	ip := "10.10.10.10"
	status := NewStatus()
	peerState := PeerState{
		PubKey: key,
	}

	status.Peers[key] = peerState

	peerState.IP = ip

	err := status.UpdatePeerStatus(peerState)
	assert.NoError(t, err, "shouldn't return error")

	state, exists := status.Peers[key]
	assert.True(t, exists, "state should be found")
	assert.Equal(t, ip, state.IP, "ip should be equal")
}

func TestRemovePeer(t *testing.T) {
	key := "abc"
	status := NewStatus()
	peerState := PeerState{
		PubKey: key,
	}

	status.Peers[key] = peerState

	err := status.RemovePeer(peerState)
	assert.NoError(t, err, "shouldn't return error")

	_, exists := status.Peers[key]
	assert.False(t, exists, "state value shouldn't be found")
}

func TestUpdateSignalStatus(t *testing.T) {
	signalState := SignalState{
		URL:       "https://signal",
		Connected: true,
	}
	status := NewStatus()

	err := status.UpdateSignalStatus(signalState)
	assert.NoError(t, err, "shouldn't return error")

	assert.Equal(t, signalState, status.Signal, "signal status should be equal")
}

func TestUpdateManagementStatus(t *testing.T) {
	managementState := ManagementState{
		URL:       "https://signal",
		Connected: true,
	}
	status := NewStatus()

	err := status.UpdateManagementStatus(managementState)
	assert.NoError(t, err, "shouldn't return error")

	assert.Equal(t, managementState, status.Management, "management status should be equal")
}

func TestGetStatus(t *testing.T) {
	key1 := "abc"
	key2 := "def"
	managementState := ManagementState{
		URL:       "https://signal",
		Connected: true,
	}
	signalState := SignalState{
		URL:       "https://signal",
		Connected: true,
	}
	peerState1 := PeerState{
		PubKey: key1,
	}

	peerState2 := PeerState{
		PubKey: key2,
	}

	status := NewStatus()

	err := status.UpdateManagementStatus(managementState)
	assert.NoError(t, err, "shouldn't return error")

	err = status.UpdateSignalStatus(signalState)
	assert.NoError(t, err, "shouldn't return error")

	err = status.AddPeer(peerState1)
	assert.NoError(t, err, "shouldn't return error")

	err = status.AddPeer(peerState2)
	assert.NoError(t, err, "shouldn't return error")

	fullStatus := status.GetStatus()

	assert.Equal(t, managementState, fullStatus.ManagementState, "management status should be equal")
	assert.Equal(t, signalState, fullStatus.SignalState, "signal status should be equal")
	assert.ElementsMatch(t, []PeerState{peerState1, peerState2}, fullStatus.Peers, "peers states should match")
}
