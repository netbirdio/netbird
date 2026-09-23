package manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// recordingStore captures the two writes the activity manager makes. The
// embedded interface satisfies the rest and panics if anything else is called,
// which keeps the manager honest about its surface.
type recordingStore struct {
	store.Store
	logins []loginWrite
	seen   []seenWrite
}

type loginWrite struct {
	accountID string
	userID    string
	at        time.Time
}

type seenWrite struct {
	accountID   string
	peerID      string
	staleBefore time.Time
}

func (s *recordingStore) SaveUserLastLogin(_ context.Context, accountID, userID string, lastLogin time.Time) error {
	s.logins = append(s.logins, loginWrite{accountID: accountID, userID: userID, at: lastLogin})
	return nil
}

func (s *recordingStore) RefreshPeerLastSeen(_ context.Context, accountID, peerID string, staleBefore time.Time) (bool, error) {
	s.seen = append(s.seen, seenWrite{accountID: accountID, peerID: peerID, staleBefore: staleBefore})
	return true, nil
}

func TestRecordUserLogin(t *testing.T) {
	tests := []struct {
		name        string
		user        *types.User
		expectWrite bool
	}{
		{
			name:        "regular user is recorded",
			user:        &types.User{Id: "user1", AccountID: "account1"},
			expectWrite: true,
		},
		{
			// Activity accounting never counts service users, so a row for one
			// would be noise.
			name:        "service user is ignored",
			user:        &types.User{Id: "svc1", AccountID: "account1", IsServiceUser: true},
			expectWrite: false,
		},
		{
			name:        "missing user is ignored",
			user:        nil,
			expectWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &recordingStore{}
			require.NoError(t, NewManager(st).RecordUserLogin(context.Background(), "account1", tt.user))

			if !tt.expectWrite {
				assert.Empty(t, st.logins, "no login should have been recorded")
				return
			}

			require.Len(t, st.logins, 1, "exactly one login should have been recorded")
			assert.Equal(t, "account1", st.logins[0].accountID, "login must be recorded against the service account")
			assert.Equal(t, tt.user.Id, st.logins[0].userID, "login must be recorded against the signing-in user")
			assert.Equal(t, time.UTC, st.logins[0].at.Location(), "timestamps are written in UTC")
			assert.WithinDuration(t, time.Now().UTC(), st.logins[0].at, time.Minute, "login should be stamped now")
		})
	}
}

func TestRecordPeerSeen(t *testing.T) {
	tests := []struct {
		name        string
		peer        *peer.Peer
		expectWrite bool
	}{
		{
			name:        "peer seen long ago is recorded",
			peer:        &peer.Peer{ID: "peer1", Status: &peer.PeerStatus{LastSeen: time.Now().Add(-3 * time.Hour)}},
			expectWrite: true,
		},
		{
			name:        "peer never seen is recorded",
			peer:        &peer.Peer{ID: "peer1", Status: &peer.PeerStatus{}},
			expectWrite: true,
		},
		{
			// The throttle. The caller already holds the peer, so skipping a
			// recently seen one costs nothing.
			name:        "peer seen inside the interval is skipped",
			peer:        &peer.Peer{ID: "peer1", Status: &peer.PeerStatus{LastSeen: time.Now().Add(-10 * time.Minute)}},
			expectWrite: false,
		},
		{
			name:        "embedded proxy peer is skipped",
			peer:        &peer.Peer{ID: "peer1", ProxyMeta: peer.ProxyMeta{Embedded: true}, Status: &peer.PeerStatus{LastSeen: time.Now().Add(-3 * time.Hour)}},
			expectWrite: false,
		},
		{
			name:        "browser client is skipped",
			peer:        &peer.Peer{ID: "peer1", Meta: peer.PeerSystemMeta{KernelVersion: "wasm"}, Status: &peer.PeerStatus{LastSeen: time.Now().Add(-3 * time.Hour)}},
			expectWrite: false,
		},
		{
			name:        "missing peer is ignored",
			peer:        nil,
			expectWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &recordingStore{}
			require.NoError(t, NewManager(st).RecordPeerSeen(context.Background(), "account1", tt.peer))

			if !tt.expectWrite {
				assert.Empty(t, st.seen, "no activity should have been recorded")
				return
			}

			require.Len(t, st.seen, 1, "exactly one activity write should have been recorded")
			assert.Equal(t, "account1", st.seen[0].accountID, "activity must be recorded against the service account")
			assert.Equal(t, tt.peer.ID, st.seen[0].peerID, "activity must be recorded against the calling peer")
			assert.Equal(t, time.UTC, st.seen[0].staleBefore.Location(), "cutoffs are passed in UTC")
			assert.WithinDuration(t, time.Now().UTC().Add(-peerSeenInterval), st.seen[0].staleBefore, time.Minute,
				"the store must enforce the same interval the local check applies")
		})
	}
}
