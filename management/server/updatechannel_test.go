package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/telemetry"
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

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		t.Fatalf("failed to create metrics: %v", err)
	}
	peersUpdater := NewPeersUpdateManager(metrics)
	update1 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 0,
		},
	}}
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}

	resultCh := make(chan struct {
		msg *UpdateMessage
		ok  bool
	}, 1)

	go func() {
		for range [channelBufferSize]int{} {
			msg, ok := peersUpdater.peerChannels[peer].Pop(context.Background())
			resultCh <- struct {
				msg *UpdateMessage
				ok  bool
			}{msg, ok}
		}
	}()

	peersUpdater.SendUpdate(context.Background(), peer, update1)
	select {
	case <-resultCh:
	case <-time.After(1 * time.Second):
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
		case updateReader := <-resultCh:
			if updateReader.msg.Update.NetworkMap.Serial == update2.Update.NetworkMap.Serial {
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
