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
// holding instance and the session token belong to the sync stream that owns the
// peer's session, and a blind write here would corrupt its fencing. This is why
// SavePeerStatus is not reused for an activity bump.
func TestRefreshPeerLastSeenLeavesSessionStateAlone(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)

	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))))
	applied, err := store.ConnectPeer(ctx, activityAccountID, "activityPeer", "instance-1", 1234567890)
	require.NoError(t, err)
	require.True(t, applied)
	setPeerLastSeen(t, store, "activityPeer", time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	require.True(t, refreshed, "the peer is stale enough to refresh")

	conn := getPeerConnection(t, store, "activityPeer")
	require.NotNil(t, conn)
	assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "activityPeer"), time.Minute, "last seen should move forward")
	assert.Equal(t, "instance-1", instanceOf(conn), "the holding instance must survive an activity write")
	assert.Equal(t, int64(1234567890), conn.SessionStartedAt, "session token must survive an activity write")
}

// TestPeerReadsAsDisconnectedWhenStale covers a management instance that stopped
// without releasing its peers: their connection rows stay, so reads must fall back to
// the instance's LastSeen, both when loading the peer and when filtering on it.
func TestPeerReadsAsDisconnectedWhenStale(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		instanceAge   time.Duration
		wantConnected bool
	}{
		{name: "instance seen within StaleAfter", instanceAge: time.Minute, wantConnected: true},
		{name: "instance not seen for longer than StaleAfter", instanceAge: nbpeer.StaleAfter + time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newActivityTestStore(t)
			require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(time.Now().UTC().Add(-time.Hour))))
			require.NoError(t, store.RegisterInstance(ctx, "instance-1", "host"))
			applied, err := store.ConnectPeer(ctx, activityAccountID, "activityPeer", "instance-1", 1)
			require.NoError(t, err)
			require.True(t, applied)
			ageInstance(t, store, "instance-1", tt.instanceAge)

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
