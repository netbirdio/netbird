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

func TestRefreshPeerLastSeen(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := time.Now().UTC().Add(-3 * time.Hour)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(stored)))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.True(t, refreshed, "a peer seen three hours ago is stale enough to refresh")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should be stamped at write time")
	assert.True(t, peer.Status.LastSeen.After(stored), "last seen must move forward")
}

// TestRefreshPeerLastSeenHonoursCutoff covers the throttle the caller relies on:
// two concurrent requests both read the same stale peer, but only the statement
// that still finds LastSeen behind the cutoff writes.
func TestRefreshPeerLastSeenHonoursCutoff(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := time.Now().UTC().Add(-10 * time.Minute)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(stored)))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.False(t, refreshed, "a peer seen inside the interval must not be written")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, stored, peer.Status.LastSeen.UTC(), time.Second, "last seen must be left where it was")
}

// TestRefreshPeerLastSeenRecordsNeverSeenPeer covers the nullable column. Status
// is an embedded pointer, so a peer stored without one leaves last seen NULL,
// and NULL loses the cutoff comparison — such a peer would never record its
// first activity.
func TestRefreshPeerLastSeenRecordsNeverSeenPeer(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := activityPeer(time.Time{})
	stored.Status = nil
	require.NoError(t, store.AddPeerToAccount(ctx, stored))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.True(t, refreshed, "a peer that was never seen must record its first activity")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should be stamped at write time")
}

// TestRefreshPeerLastSeenLeavesSessionStateAlone pins the column boundary: the
// connected flag and the session token belong to the sync stream that owns the
// peer's session, and a blind write here would corrupt its fencing. This is why
// SavePeerStatus is not reused for an activity bump.
func TestRefreshPeerLastSeenLeavesSessionStateAlone(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)

	stored := activityPeer(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	stored.Status.Connected = true
	stored.Status.SessionStartedAt = 1234567890
	require.NoError(t, store.AddPeerToAccount(ctx, stored))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	require.True(t, refreshed, "the peer is stale enough to refresh")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should move forward")
	assert.True(t, peer.Status.Connected, "connected flag must survive an activity write")
	assert.Equal(t, int64(1234567890), peer.Status.SessionStartedAt, "session token must survive an activity write")
}

// TestPeerReadsAsDisconnectedWhenStale covers a management instance that stopped
// without marking its peers disconnected: the stored flag stays set, so reads must
// fall back to LastSeen, both when loading the peer and when filtering on it.
func TestPeerReadsAsDisconnectedWhenStale(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		lastSeen      time.Time
		wantConnected bool
	}{
		{name: "seen within StaleAfter", lastSeen: time.Now().UTC().Add(-time.Minute), wantConnected: true},
		{name: "not seen for longer than StaleAfter", lastSeen: time.Now().UTC().Add(-nbpeer.StaleAfter - time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newActivityTestStore(t)
			stored := activityPeer(tt.lastSeen)
			stored.Status.Connected = true
			require.NoError(t, store.AddPeerToAccount(ctx, stored))

			peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
			require.NoError(t, err)
			assert.Equal(t, tt.wantConnected, peer.Status.Connected)

			for _, connected := range []bool{true, false} {
				peers, _, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, activityAccountID, PaginationState{}, PeerFilters{Connected: &connected}, PeerSorting{})
				require.NoError(t, err)
				if connected == tt.wantConnected {
					assert.Len(t, peers, 1, "filter connected=%t", connected)
				} else {
					assert.Empty(t, peers, "filter connected=%t", connected)
				}
			}
		})
	}
}

func TestHeartbeatPeerSession(t *testing.T) {
	ctx := context.Background()
	const session = int64(1234567890)
	stale := time.Now().UTC().Add(-time.Hour)

	tests := []struct {
		name          string
		storedSession int64
		loginExpired  bool
		session       int64
		wantUpdated   bool
	}{
		{name: "stream that owns the session", storedSession: session, session: session, wantUpdated: true},
		{name: "login expired while the stream stayed open", storedSession: session, loginExpired: true, session: session},
		{name: "session replaced by a newer stream", storedSession: session + 1, session: session},
		{name: "session already ended", session: session},
		{name: "zero token never matches", session: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newActivityTestStore(t)
			stored := activityPeer(stale)
			stored.Status.SessionStartedAt = tt.storedSession
			stored.Status.LoginExpired = tt.loginExpired
			require.NoError(t, store.AddPeerToAccount(ctx, stored))

			updated, err := store.HeartbeatPeerSession(ctx, activityAccountID, "activityPeer", tt.session)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
			require.NoError(t, err)
			assert.Equal(t, tt.storedSession, peer.Status.SessionStartedAt, "the session token must never change")
			if tt.wantUpdated {
				assert.True(t, peer.Status.Connected, "a heartbeat must undo a connected flag that was saved back as false")
				assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute)
				return
			}
			assert.False(t, peer.Status.Connected)
			assert.WithinDuration(t, stale, peer.Status.LastSeen.UTC(), time.Second)
		})
	}
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
