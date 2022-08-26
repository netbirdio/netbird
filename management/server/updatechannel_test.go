package server

import (
	"github.com/netbirdio/netbird/management/proto"
	"testing"
)

//var peersUpdater *PeersUpdateManager

func TestCreateChannel(t *testing.T) {
	peer := "test-create"
	peersUpdater := NewPeersUpdateManager()
	defer peersUpdater.CloseChannel(peer)

	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
}

func TestSendUpdate(t *testing.T) {
	peer := "test-sendupdate"
	peersUpdater := NewPeersUpdateManager()
	update := &UpdateMessage{Update: &proto.SyncResponse{}}
	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	err := peersUpdater.SendUpdate(peer, update)
	if err != nil {
		t.Error("Error sending update: ", err)
	}
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}

	for range [channelBufferSize]int{} {
		err = peersUpdater.SendUpdate(peer, update)
		if err != nil {
			t.Errorf("got an early error sending update: %v ", err)
		}
	}

	err = peersUpdater.SendUpdate(peer, update)
	if err == nil {
		t.Error("should have returned an error with channel full")
	}

}

func TestCloseChannel(t *testing.T) {
	peer := "test-close"
	peersUpdater := NewPeersUpdateManager()
	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.CloseChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}
