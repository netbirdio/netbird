package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
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

func TestCancelPeerRoutines_DrainingQueuesDisconnect(t *testing.T) {
	streamStart := time.Unix(1700000000, 0)

	tests := []struct {
		name         string
		embedded     bool
		draining     bool
		flushBefore  bool
		wantQueued   bool
		wantOwnWrite bool
	}{
		{name: "regular peer while draining is queued", draining: true, wantQueued: true},
		{name: "embedded proxy peer while draining writes its own disconnect", embedded: true, draining: true, wantOwnWrite: true},
		{name: "regular peer without draining writes its own disconnect", wantOwnWrite: true},
		{name: "regular peer after the flush writes its own disconnect", draining: true, flushBefore: true, wantOwnWrite: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			accountManager := account.NewMockManager(ctrl)
			controller := network_map.NewMockController(ctrl)
			secretsManager := NewMockSecretsManager(ctrl)
			s := &Server{accountManager: accountManager, networkMapController: controller, secretsManager: secretsManager}

			peer := &nbpeer.Peer{ID: "peer-1", Key: "peer-key"}
			peer.ProxyMeta.Embedded = tt.embedded

			if tt.draining {
				s.StartDraining()
			}
			if tt.flushBefore {
				s.FlushDisconnects(context.Background())
			}

			if tt.wantOwnWrite {
				accountManager.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.Key, streamStart).Return(nil)
			}
			controller.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.ID, gomock.Any()).Return(true)
			secretsManager.EXPECT().CancelRefresh(peer.ID)
			accountManager.EXPECT().UntrackCertificateChallenges("account-1", peer.ID, streamStart)

			s.cancelPeerRoutines(context.Background(), "account-1", peer, streamStart, nil)

			if tt.wantQueued {
				accountManager.EXPECT().MarkPeersDisconnected(gomock.Any(), []types.PeerSession{
					{AccountID: "account-1", PeerID: peer.ID, SessionStartedAt: streamStart.UnixNano()},
				}).Return(nil)
			}
			s.FlushDisconnects(context.Background())
		})
	}
}

func TestFlushDisconnects_FailedBatchStopsDraining(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountManager := account.NewMockManager(ctrl)
	controller := network_map.NewMockController(ctrl)
	secretsManager := NewMockSecretsManager(ctrl)
	s := &Server{accountManager: accountManager, networkMapController: controller, secretsManager: secretsManager}

	peer := &nbpeer.Peer{ID: "peer-1", Key: "peer-key"}
	first := time.Unix(1700000000, 0)
	second := first.Add(time.Second)
	controller.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.ID, gomock.Any()).Return(true).Times(2)
	secretsManager.EXPECT().CancelRefresh(peer.ID).Times(2)
	accountManager.EXPECT().UntrackCertificateChallenges("account-1", peer.ID, gomock.Any()).Times(2)

	s.StartDraining()
	s.cancelPeerRoutines(context.Background(), "account-1", peer, first, nil)

	accountManager.EXPECT().MarkPeersDisconnected(gomock.Any(), gomock.Any()).Return(errors.New("db down")).Times(2)
	s.FlushDisconnects(context.Background())

	accountManager.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.Key, second).Return(nil)
	s.cancelPeerRoutines(context.Background(), "account-1", peer, second, nil)
}

func TestFlushDisconnects_RetriesFailedBatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountManager := account.NewMockManager(ctrl)
	controller := network_map.NewMockController(ctrl)
	secretsManager := NewMockSecretsManager(ctrl)
	s := &Server{accountManager: accountManager, networkMapController: controller, secretsManager: secretsManager}

	peer := &nbpeer.Peer{ID: "peer-1", Key: "peer-key"}
	streamStart := time.Unix(1700000000, 0)
	controller.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.ID, gomock.Any()).Return(true)
	secretsManager.EXPECT().CancelRefresh(peer.ID)
	accountManager.EXPECT().UntrackCertificateChallenges("account-1", peer.ID, streamStart)

	s.StartDraining()
	s.cancelPeerRoutines(context.Background(), "account-1", peer, streamStart, nil)

	want := []types.PeerSession{{AccountID: "account-1", PeerID: peer.ID, SessionStartedAt: streamStart.UnixNano()}}
	gomock.InOrder(
		accountManager.EXPECT().MarkPeersDisconnected(gomock.Any(), want).Return(errors.New("deadlock detected")),
		accountManager.EXPECT().MarkPeersDisconnected(gomock.Any(), want).Return(nil),
	)
	s.FlushDisconnects(context.Background())
}

func TestCancelPeerRoutines_QueuesDisconnectBeforeWaitingForPeerLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountManager := account.NewMockManager(ctrl)
	controller := network_map.NewMockController(ctrl)
	secretsManager := NewMockSecretsManager(ctrl)
	s := &Server{accountManager: accountManager, networkMapController: controller, secretsManager: secretsManager}

	peer := &nbpeer.Peer{ID: "peer-1", Key: "peer-key"}
	streamStart := time.Unix(1700000000, 0)
	controller.EXPECT().OnPeerDisconnected(gomock.Any(), "account-1", peer.ID, gomock.Any()).Return(true)
	secretsManager.EXPECT().CancelRefresh(peer.ID)
	accountManager.EXPECT().UntrackCertificateChallenges("account-1", peer.ID, streamStart)

	unlock := s.acquirePeerLockByUID(context.Background(), peer.Key)
	var unlockOnce sync.Once
	t.Cleanup(func() { unlockOnce.Do(unlock) })
	s.StartDraining()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.cancelPeerRoutines(context.Background(), "account-1", peer, streamStart, nil)
	}()

	require.Eventually(t, func() bool {
		s.drainMu.Lock()
		defer s.drainMu.Unlock()
		return len(s.pendingDisconnects) == 1
	}, time.Second, 5*time.Millisecond, "the disconnect must be queued while the teardown waits for the peer lock")

	accountManager.EXPECT().MarkPeersDisconnected(gomock.Any(), []types.PeerSession{
		{AccountID: "account-1", PeerID: peer.ID, SessionStartedAt: streamStart.UnixNano()},
	}).Return(nil)
	s.FlushDisconnects(context.Background())

	unlockOnce.Do(unlock)
	<-done
}
