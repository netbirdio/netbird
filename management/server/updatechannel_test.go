package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/stretchr/testify/assert"
)

// var peersUpdater *PeersUpdateManager

func TestCreateChannel(t *testing.T) {
	peer := "test-create"
	peersUpdater := NewPeersUpdateManager(nil)
	defer peersUpdater.CloseChannel(context.Background(), peer)

	_ = peersUpdater.CreateChannel(context.Background(), peer)
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
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.SendUpdate(context.Background(), peer, update1)
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}

	for range [channelBufferSize]int{} {
		peersUpdater.SendUpdate(context.Background(), peer, update1)
	}

	update2 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 10,
		},
	}}

	peersUpdater.SendUpdate(context.Background(), peer, update2)
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
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.CloseChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}

func TestHandlePeerMessageUpdate(t *testing.T) {
	tests := []struct {
		name           string
		peerID         string
		existingUpdate *UpdateMessage
		newUpdate      *UpdateMessage
		expectedResult bool
	}{
		{
			name:   "update message with turn credentials update",
			peerID: "peer",
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					WiretrusteeConfig: &proto.WiretrusteeConfig{},
				},
			},
			expectedResult: true,
		},
		{
			name:   "update message for peer without existing update",
			peerID: "peer1",
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
			},
			expectedResult: true,
		},
		{
			name:   "update message with no changes in update",
			peerID: "peer2",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			expectedResult: false,
		},
		{
			name:   "update message with changes in checks",
			peerID: "peer3",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 2},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
				Checks:     []*posture.Checks{{ID: "check1"}},
			},
			expectedResult: true,
		},
		{
			name:   "update message with lower serial number",
			peerID: "peer4",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 2},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPeersUpdateManager(nil)
			ctx := context.Background()

			if tt.existingUpdate != nil {
				p.peerUpdateMessage[tt.peerID] = tt.existingUpdate
			}

			result := p.handlePeerMessageUpdate(ctx, tt.peerID, tt.newUpdate)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
