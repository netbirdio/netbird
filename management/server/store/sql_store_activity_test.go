package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

const activityAccountID = "activityAccountId"

func newActivityTestStore(t *testing.T) Store {
	t.Helper()

	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	require.NoError(t, store.SaveAccount(context.Background(), &types.Account{
		Id:        activityAccountID,
		Domain:    "activity.example.com",
		CreatedAt: time.Now().UTC(),
	}))

	return store
}

func TestRefreshUserLastLogin(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		stored  *time.Time
		loginAt time.Time
		expect  *time.Time
	}{
		{
			// A user who has only ever reached proxy services has no login on
			// record at all, and activity accounting skips those users.
			name:    "never logged in gets the timestamp",
			stored:  nil,
			loginAt: base,
			expect:  &base,
		},
		{
			name:    "older timestamp moves forward",
			stored:  ptrTime(base.Add(-2 * time.Hour)),
			loginAt: base,
			expect:  &base,
		},
		{
			name:    "newer timestamp is left alone",
			stored:  ptrTime(base.Add(time.Hour)),
			loginAt: base,
			expect:  ptrTime(base.Add(time.Hour)),
		},
		{
			name:    "zero login is ignored",
			stored:  ptrTime(base),
			loginAt: time.Time{},
			expect:  ptrTime(base),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newActivityTestStore(t)

			require.NoError(t, store.SaveUser(ctx, &types.User{
				Id:        "activityUser",
				AccountID: activityAccountID,
				Role:      types.UserRoleUser,
				Issued:    "api",
				LastLogin: tt.stored,
				CreatedAt: base.Add(-24 * time.Hour),
			}))

			require.NoError(t, store.RefreshUserLastLogin(ctx, activityAccountID, "activityUser", tt.loginAt))

			user, err := store.GetUserByUserID(ctx, LockingStrengthNone, "activityUser")
			require.NoError(t, err)
			require.NotNil(t, user.LastLogin, "user should have a login timestamp")
			assert.WithinDuration(t, *tt.expect, user.LastLogin.UTC(), time.Second, "unexpected stored last login")
		})
	}
}

func TestRefreshUserLastLoginUnknownUserIsNotAnError(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)

	// The write is best-effort telemetry on an auth path; a row that no longer
	// exists must not surface as a failure to the caller.
	assert.NoError(t, store.RefreshUserLastLogin(ctx, activityAccountID, "goneUser", time.Now().UTC()))
}

func TestRefreshPeerLastSeen(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))))

	seenAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", seenAt))

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, seenAt, peer.Status.LastSeen.UTC(), time.Second, "unexpected stored last seen")
}

func TestRefreshPeerLastSeenZeroIsIgnored(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(stored)))

	require.NoError(t, store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Time{}))

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, stored, peer.Status.LastSeen.UTC(), time.Second, "a zero timestamp must not clear last seen")
}

// TestRefreshPeerLastSeenLeavesSessionStateAlone pins the column boundary: the
// connected flag and the session token belong to the sync stream that owns the
// peer's session, and a blind write here would corrupt its fencing.
func TestRefreshPeerLastSeenLeavesSessionStateAlone(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)

	stored := activityPeer(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	stored.Status.Connected = true
	stored.Status.SessionStartedAt = 1234567890
	require.NoError(t, store.AddPeerToAccount(ctx, stored))

	seenAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", seenAt))

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, seenAt, peer.Status.LastSeen.UTC(), time.Second, "last seen should move forward")
	assert.True(t, peer.Status.Connected, "connected flag must survive an activity write")
	assert.Equal(t, int64(1234567890), peer.Status.SessionStartedAt, "session token must survive an activity write")
}

func activityPeer(lastSeen time.Time) *nbpeer.Peer {
	return &nbpeer.Peer{
		ID:        "activityPeer",
		AccountID: activityAccountID,
		Key:       "activityPeerKey",
		IP:        netip.MustParseAddr("100.64.0.9"),
		Name:      "activity-peer",
		DNSLabel:  "activity-peer",
		Status:    &nbpeer.PeerStatus{LastSeen: lastSeen},
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
