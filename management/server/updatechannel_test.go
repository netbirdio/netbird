package server

import (
	"github.com/wiretrustee/wiretrustee/management/proto"
	"testing"
)

var peersUpdater *PeersUpdateManager

const peer = "peer-representation"

func TestCreateChannel(t *testing.T) {
	peersUpdater = NewPeersUpdateManager()

	channel := peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	if peersUpdater.peerChannels[peer] != channel {
		t.Error("Channel wasn't created.")
	}
}

func TestSendUpdate(t *testing.T) {
	update := &UpdateMessage{Update: &proto.SyncResponse{}}
	err := peersUpdater.SendUpdate(peer, update)
	if err != nil {
		t.Error("Error sending update: ", err)
	}
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}
}

func TestCloseChannel(t *testing.T) {
	peersUpdater.CloseChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}
