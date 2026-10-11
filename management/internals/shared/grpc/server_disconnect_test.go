package grpc

import (
	"context"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestCancelPeerRoutines_SessionOwnership(t *testing.T) {
	peer := &nbpeer.Peer{ID: "peer-1", Key: "peer-key"}
	streamStart := time.Unix(1700000000, 0)
	session := make(chan *network_map.UpdateMessage)

	tests := []struct {
		name          string
		session       chan *network_map.UpdateMessage
		ownsPeer      bool
		cancelRefresh bool
	}{
		{name: "owning session tears everything down", session: session, ownsPeer: true, cancelRefresh: true},
		{name: "stale session keeps the newer session's refresh", session: session, ownsPeer: false, cancelRefresh: false},
		{name: "failed sync without a channel closes the older session", session: nil, ownsPeer: true, cancelRefresh: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			accountManager := account.NewMockManager(ctrl)
			controller := network_map.NewMockController(ctrl)
			secretsManager := NewMockSecretsManager(ctrl)
			s := &Server{accountManager: accountManager, networkMapController: controller, secretsManager: secretsManager}

			accountManager.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.Key, streamStart).Return(nil)
			controller.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.ID, tt.session).Return(tt.ownsPeer)
			if tt.cancelRefresh {
				secretsManager.EXPECT().CancelRefresh(peer.ID)
				// The stream's challenge renewal ends with it; a stale session leaves the
				// newer one's alone.
				accountManager.EXPECT().UntrackCertificateChallenges("account-1", peer.ID, streamStart)
			}

			s.cancelPeerRoutines(context.Background(), "account-1", peer, streamStart, tt.session)
		})
	}
}
