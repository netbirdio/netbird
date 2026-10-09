package update_channel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/shared/management/proto"
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
	update1 := &network_map.UpdateMessage{
		Update: &proto.SyncResponse{
			NetworkMap: &proto.NetworkMap{
				Serial: 0,
			},
		},
		MessageType: network_map.MessageTypeNetworkMap,
	}
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

	update2 := &network_map.UpdateMessage{
		Update: &proto.SyncResponse{
			NetworkMap: &proto.NetworkMap{
				Serial: 10,
			},
		},
		MessageType: network_map.MessageTypeNetworkMap,
	}

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

func TestCloseSessionChannel(t *testing.T) {
	ctx := context.Background()
	const peer = "test-close-session"

	t.Run("own channel is closed", func(t *testing.T) {
		peersUpdater := NewPeersUpdateManager(nil)
		session := peersUpdater.CreateChannel(ctx, peer)

		require.True(t, peersUpdater.CloseSessionChannel(ctx, peer, session))
		assert.False(t, peersUpdater.HasChannel(peer))
		_, open := <-session
		assert.False(t, open, "own channel must be closed")
	})

	t.Run("newer session channel is kept", func(t *testing.T) {
		peersUpdater := NewPeersUpdateManager(nil)
		stale := peersUpdater.CreateChannel(ctx, peer)
		current := peersUpdater.CreateChannel(ctx, peer)

		require.False(t, peersUpdater.CloseSessionChannel(ctx, peer, stale))
		require.True(t, peersUpdater.HasChannel(peer))
		assert.Equal(t, current, peersUpdater.peerChannels[peer])

		peersUpdater.SendUpdate(ctx, peer, &network_map.UpdateMessage{})
		select {
		case _, open := <-current:
			assert.True(t, open, "newer session channel must stay open")
		default:
			t.Fatal("newer session channel did not receive the update")
		}
	})

	t.Run("no registered channel", func(t *testing.T) {
		peersUpdater := NewPeersUpdateManager(nil)
		session := peersUpdater.CreateChannel(ctx, peer)
		peersUpdater.CloseChannel(ctx, peer)

		assert.True(t, peersUpdater.CloseSessionChannel(ctx, peer, session))
		assert.True(t, peersUpdater.CloseSessionChannel(ctx, peer, nil))
	})

	t.Run("nil session closes the registered channel", func(t *testing.T) {
		peersUpdater := NewPeersUpdateManager(nil)
		current := peersUpdater.CreateChannel(ctx, peer)

		require.True(t, peersUpdater.CloseSessionChannel(ctx, peer, nil))
		assert.False(t, peersUpdater.HasChannel(peer))
		_, open := <-current
		assert.False(t, open, "registered channel must be closed")
	})
}
