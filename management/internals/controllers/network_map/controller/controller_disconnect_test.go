package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type recordingEphemeralManager struct {
	disconnected []string
}

func (r *recordingEphemeralManager) LoadInitialPeers(context.Context)              {}
func (r *recordingEphemeralManager) Stop()                                         {}
func (r *recordingEphemeralManager) OnPeerConnected(context.Context, *nbpeer.Peer) {}
func (r *recordingEphemeralManager) OnPeerDisconnected(_ context.Context, peer *nbpeer.Peer) {
	r.disconnected = append(r.disconnected, peer.ID)
}

func TestOnPeerDisconnected_OwnSession(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository(gomock.NewController(t))
	ephemeralManager := &recordingEphemeralManager{}
	updateManager := update_channel.NewPeersUpdateManager(nil)
	c := Controller{repo: repo, peersUpdateManager: updateManager, EphemeralPeersManager: ephemeralManager}

	session := updateManager.CreateChannel(ctx, "peer-1")
	repo.EXPECT().GetPeerByID(gomock.Any(), "account-1", "peer-1").Return(&nbpeer.Peer{ID: "peer-1", Ephemeral: true}, nil)

	require.True(t, c.OnPeerDisconnected(ctx, "account-1", "peer-1", session))
	assert.False(t, updateManager.HasChannel("peer-1"))
	assert.Equal(t, []string{"peer-1"}, ephemeralManager.disconnected)
}

func TestOnPeerDisconnected_NewerSessionOwnsPeer(t *testing.T) {
	ctx := context.Background()
	ephemeralManager := &recordingEphemeralManager{}
	updateManager := update_channel.NewPeersUpdateManager(nil)
	c := Controller{repo: NewMockRepository(gomock.NewController(t)), peersUpdateManager: updateManager, EphemeralPeersManager: ephemeralManager}

	stale := updateManager.CreateChannel(ctx, "peer-1")
	current := updateManager.CreateChannel(ctx, "peer-1")

	require.False(t, c.OnPeerDisconnected(ctx, "account-1", "peer-1", stale))
	require.True(t, updateManager.HasChannel("peer-1"))
	updateManager.SendUpdate(ctx, "peer-1", &network_map.UpdateMessage{})
	select {
	case _, open := <-current:
		assert.True(t, open, "newer session channel must stay open")
	default:
		t.Fatal("newer session channel did not receive the update")
	}
	assert.Empty(t, ephemeralManager.disconnected, "a live peer must not be scheduled for ephemeral cleanup")
}
