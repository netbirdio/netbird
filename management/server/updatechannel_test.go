package server

import (
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/proto"
)

//var peersUpdater *PeersUpdateManager

func TestCreateChannel(t *testing.T) {
	peer := "test-create"
	peersUpdater := NewPeersUpdateManager(nil)
	defer peersUpdater.CloseChannel(peer)

	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
}

func TestSendUpdate(t *testing.T) {
	peer := "test-sendupdate"
	peersUpdater := NewPeersUpdateManager(nil)
	update1 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 0,
		},
	}}
	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.SendUpdate(peer, update1)
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}

	for range [channelBufferSize]int{} {
		peersUpdater.SendUpdate(peer, update1)
	}

	update2 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 10,
		},
	}}

	peersUpdater.SendUpdate(peer, update2)
	timeout := time.After(5 * time.Second)
	for range [channelBufferSize]int{} {
		select {
		case <-timeout:
			t.Error("timed out reading previously sent updates")
		case updateReader := <-peersUpdater.peerChannels[peer]:
			if updateReader.Update.NetworkMap.Serial == update2.Update.NetworkMap.Serial {
				t.Error("got the update that shouldn't have been sent")
			}
		}
	}

}

func TestCloseChannel(t *testing.T) {
	peer := "test-close"
	peersUpdater := NewPeersUpdateManager(nil)
	_ = peersUpdater.CreateChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.CloseChannel(peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}
