package store

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/shared/testing_helpers"
)

// TestSqlStore_GetPeerByIP_NotFound pins the not-found semantics the
// proxy's ValidateTunnelPeer relies on: a tunnel-IP that isn't in the
// account roster must surface as a NotFound error (not a generic
// Internal) so callers can distinguish an expected miss from a real
// store failure. A known IP still resolves.
func TestSqlStore_GetPeerByIP_NotFound(t *testing.T) {
	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		peer, err := store.GetPeerByIP(context.Background(), LockingStrengthNone, accountID, net.ParseIP("192.168.0.0"))
		require.NoError(t, err, "known tunnel IP must resolve")
		require.NotNil(t, peer)

		_, err = store.GetPeerByIP(context.Background(), LockingStrengthNone, accountID, net.ParseIP("100.65.0.99"))
		require.Error(t, err, "unknown tunnel IP must error")
		parsedErr, ok := status.FromError(err)
		require.True(t, ok, "error must be a status error")
		require.Equal(t, status.NotFound, parsedErr.Type(), "tunnel-IP miss must be NotFound, not Internal")
	})
}

func TestSqlStore_SavePeer(t *testing.T) {
	populateFields := testing_helpers.NewPopulateFields()

	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
		require.NoError(t, err)

		metadata := nbpeer.PeerSystemMeta{}
		reflectedMetadata := reflect.ValueOf(&metadata).Elem()

		numOfFields, err := populateFields.PopulateAll(reflectedMetadata)
		assert.NoError(t, err)
		assert.Equal(t, 33, numOfFields)

		// save status of non-existing peer
		peer := &nbpeer.Peer{
			Key:       "peerkey",
			ID:        "testpeer",
			IP:        netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			IPv6:      netip.MustParseAddr("fd00::1"),
			Meta:      metadata, //nbpeer.PeerSystemMeta{Hostname: "testingpeer"},
			Name:      "peer name",
			Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
			CreatedAt: time.Now().UTC(),
		}
		ctx := context.Background()
		err = store.SavePeer(ctx, account.Id, peer)
		assert.Error(t, err)
		parsedErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

		// save new status of existing peer
		account.Peers[peer.ID] = peer

		err = store.SaveAccount(context.Background(), account)
		require.NoError(t, err)

		updatedPeer := peer.Copy()
		updatedPeer.Status.Connected = false
		updatedPeer.Meta.Hostname = "updatedpeer"

		err = store.SavePeer(ctx, account.Id, updatedPeer)
		require.NoError(t, err)

		account, err = store.GetAccount(context.Background(), account.Id)
		require.NoError(t, err)

		actual := account.Peers[peer.ID]
		assert.Equal(t, updatedPeer.Meta, actual.Meta)
		assert.Equal(t, updatedPeer.Status.Connected, actual.Status.Connected)
		assert.Equal(t, updatedPeer.Status.LoginExpired, actual.Status.LoginExpired)
		assert.Equal(t, updatedPeer.Status.RequiresApproval, actual.Status.RequiresApproval)
		assert.WithinDurationf(t, updatedPeer.Status.LastSeen, actual.Status.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
	})
}

func TestSqlStore_SavePeerStatus(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(context.Background(), account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

	// save new status of existing peer
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		ID:     "testpeer",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")

	newStatus.Connected = true

	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual = account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
}

func TestSqlite_GetTakenIPs(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	takenIPs, err := store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{}, takenIPs)

	peer1 := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: existingAccountID,
		Key:       "key1",
		DNSLabel:  "peer1",
		IP:        netip.AddrFrom4([4]byte{1, 1, 1, 1}),
		IPv6:      netip.MustParseAddr("fd00::1:1:1:1"),
	}
	err = store.AddPeerToAccount(context.Background(), peer1)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	ip1 := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	assert.Equal(t, []netip.Addr{ip1}, takenIPs)

	peer2 := &nbpeer.Peer{
		ID:        "peer1second",
		AccountID: existingAccountID,
		Key:       "key2",
		DNSLabel:  "peer1-1",
		IP:        netip.AddrFrom4([4]byte{2, 2, 2, 2}),
		IPv6:      netip.MustParseAddr("fd00::2:2:2:2"),
	}
	err = store.AddPeerToAccount(context.Background(), peer2)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	ip2 := netip.AddrFrom4([4]byte{2, 2, 2, 2})
	assert.Equal(t, []netip.Addr{ip1, ip2}, takenIPs)
}

func TestSqlite_GetPeerLabelsInAccount(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		peerHostname := "peer1"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		labels, err := store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)
		assert.Equal(t, []string{}, labels)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			DNSLabel:  "peer1",
			IP:        netip.AddrFrom4([4]byte{1, 1, 1, 1}),
			IPv6:      netip.MustParseAddr("fd00::1:1:1:1"),
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)
		assert.Equal(t, []string{"peer1"}, labels)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			DNSLabel:  "peer1-1",
			IP:        netip.AddrFrom4([4]byte{2, 2, 2, 2}),
			IPv6:      netip.MustParseAddr("fd00::2:2:2:2"),
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.NoError(t, err)

		labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)

		expected := []string{"peer1", "peer1-1"}
		sort.Strings(expected)
		sort.Strings(labels)
		assert.Equal(t, expected, labels)
	})
}

func Test_AddPeerWithSameDnsLabel(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			DNSLabel:  "peer1.domain.test",
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			DNSLabel:  "peer1.domain.test",
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.Error(t, err)
	})
}

func Test_AddPeerWithSameIP(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			IP:        netip.AddrFrom4([4]byte{1, 1, 1, 1}),
			IPv6:      netip.MustParseAddr("fd00::1:1:1:1"),
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			IP:        netip.AddrFrom4([4]byte{1, 1, 1, 1}),
			IPv6:      netip.MustParseAddr("fd00::2:2:2:2"),
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.Error(t, err)
	})
}

func TestSqlStore_GetPeerByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		peerID      string
		expectError bool
	}{
		{
			name:        "retrieve existing peer",
			peerID:      "cfefqs706sqkneg59g4g",
			expectError: false,
		},
		{
			name:        "retrieve non-existing peer",
			peerID:      "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty peer ID",
			peerID:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, tt.peerID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, peer)
			} else {
				require.NoError(t, err)
				require.NotNil(t, peer)
				require.Equal(t, tt.peerID, peer.ID)
			}
		})
	}
}

func TestSqlStore_GetPeersByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name          string
		peerIDs       []string
		expectedCount int
	}{
		{
			name:          "retrieve existing peers by existing IDs",
			peerIDs:       []string{"cfefqs706sqkneg59g4g", "cfeg6sf06sqkneg59g50"},
			expectedCount: 2,
		},
		{
			name:          "empty peer IDs list",
			peerIDs:       []string{},
			expectedCount: 0,
		},
		{
			name:          "non-existing peer IDs",
			peerIDs:       []string{"nonexistent1", "nonexistent2"},
			expectedCount: 0,
		},
		{
			name:          "mixed existing and non-existing peer IDs",
			peerIDs:       []string{"cfeg6sf06sqkneg59g50", "nonexistent"},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetPeersByIDs(context.Background(), LockingStrengthNone, accountID, tt.peerIDs)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_AddPeerToAccount(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	peer := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: accountID,
		Key:       "key",
		IP:        netip.AddrFrom4([4]byte{1, 1, 1, 1}),
		IPv6:      netip.MustParseAddr("fd00::1:1:1:1"),
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "hostname",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		Name:     "peer.test",
		DNSLabel: "peer",
		Status: &nbpeer.PeerStatus{
			LastSeen:         time.Now().UTC(),
			Connected:        true,
			LoginExpired:     false,
			RequiresApproval: false,
		},
		SSHKey:                      "ssh-key",
		SSHEnabled:                  false,
		LoginExpirationEnabled:      true,
		InactivityExpirationEnabled: false,
		LastLogin:                   util.ToPtr(time.Now().UTC()),
		CreatedAt:                   time.Now().UTC(),
		Ephemeral:                   true,
	}
	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err, "failed to add peer to account")

	storedPeer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, peer.ID)
	require.NoError(t, err, "failed to get peer")

	assert.Equal(t, peer.ID, storedPeer.ID)
	assert.Equal(t, peer.AccountID, storedPeer.AccountID)
	assert.Equal(t, peer.Key, storedPeer.Key)
	assert.Equal(t, peer.IP.String(), storedPeer.IP.String())
	assert.Equal(t, peer.Meta, storedPeer.Meta)
	assert.Equal(t, peer.Name, storedPeer.Name)
	assert.Equal(t, peer.DNSLabel, storedPeer.DNSLabel)
	assert.Equal(t, peer.SSHKey, storedPeer.SSHKey)
	assert.Equal(t, peer.SSHEnabled, storedPeer.SSHEnabled)
	assert.Equal(t, peer.LoginExpirationEnabled, storedPeer.LoginExpirationEnabled)
	assert.Equal(t, peer.InactivityExpirationEnabled, storedPeer.InactivityExpirationEnabled)
	assert.WithinDurationf(t, peer.GetLastLogin(), storedPeer.GetLastLogin().UTC(), time.Millisecond, "LastLogin should be equal")
	assert.WithinDurationf(t, peer.CreatedAt, storedPeer.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	assert.Equal(t, peer.Ephemeral, storedPeer.Ephemeral)
	assert.Equal(t, peer.Status.Connected, storedPeer.Status.Connected)
	assert.Equal(t, peer.Status.LoginExpired, storedPeer.Status.LoginExpired)
	assert.Equal(t, peer.Status.RequiresApproval, storedPeer.Status.RequiresApproval)
	assert.WithinDurationf(t, peer.Status.LastSeen, storedPeer.Status.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
}

func TestSqlStore_GetAccountPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		nameFilter    string
		ipFilter      string
		expectedCount int
	}{
		{
			name:          "should retrieve peers for an existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 5,
		},
		{
			name:          "should return no peers for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers for an empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
		{
			name:          "should filter peers by name",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			nameFilter:    "expiredhost",
			expectedCount: 1,
		},
		{
			name:          "should filter peers by partial name",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			nameFilter:    "host",
			expectedCount: 4,
		},
		{
			name:          "should filter peers by ip",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			ipFilter:      "100.64.39.54",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeers(context.Background(), LockingStrengthNone, tt.accountID, tt.nameFilter, tt.ipFilter)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetAccountPeersWithExpiration(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name            string
		accountID       string
		expectedCount   int
		expectedPeerIDs []string
	}{
		{
			name:            "should retrieve only non-expired peers with expiration enabled",
			accountID:       "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount:   1,
			expectedPeerIDs: []string{"notexpired01"},
		},
		{
			name:          "should return no peers with expiration for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers with expiration for a empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeersWithExpiration(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
			for i, peer := range peers {
				assert.Equal(t, tt.expectedPeerIDs[i], peer.ID)
			}
		})
	}
}

func TestSqlStore_GetAccountPeersWithExpiration_ExcludesAlreadyExpired(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	peers, err := store.GetAccountPeersWithExpiration(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)

	// Verify the already-expired peer (cg05lnblo1hkg2j514p0) is not returned
	for _, peer := range peers {
		assert.NotEqual(t, "cg05lnblo1hkg2j514p0", peer.ID, "already expired peer should not be returned")
		assert.False(t, peer.Status.LoginExpired, "returned peers should not have LoginExpired set")
	}
}

func TestSqlStore_GetAccountPeersWithInactivity(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "should retrieve peers with inactivity for an existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "should return no peers with inactivity for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers with inactivity for an empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeersWithInactivity(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetAllEphemeralPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/storev1.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	peers, err := store.GetAllEphemeralPeers(context.Background(), LockingStrengthNone)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.True(t, peers[0].Ephemeral)
}

func TestSqlStore_GetUserPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		userID        string
		expectedCount int
	}{
		{
			name:          "should retrieve peers for existing account ID and user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "f4f6d672-63fb-11ec-90d6-0242ac120003",
			expectedCount: 1,
		},
		{
			name:          "should return no peers for non-existing account ID with existing user ID",
			accountID:     "nonexistent",
			userID:        "f4f6d672-63fb-11ec-90d6-0242ac120003",
			expectedCount: 0,
		},
		{
			name:          "should return no peers for non-existing user ID with existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "nonexistent_user",
			expectedCount: 0,
		},
		{
			name:          "should retrieve peers for another valid account ID and user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "edafee4e-63fb-11ec-90d6-0242ac120003",
			expectedCount: 3,
		},
		{
			name:          "should return no peers for existing account ID with empty user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetUserPeers(context.Background(), LockingStrengthNone, tt.accountID, tt.userID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_DeletePeer(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "csrnkiq7qv9d8aitqd50"

	err = store.DeletePeer(context.Background(), accountID, peerID)
	require.NoError(t, err)

	peer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, peerID)
	require.Error(t, err)
	require.Nil(t, peer)
}

func BenchmarkGetAccountPeers(b *testing.B) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(cleanup)

	numberOfPeers := 1000
	numberOfGroups := 200
	numberOfPeersPerGroup := 500
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	peers := make([]*nbpeer.Peer, 0, numberOfPeers)
	for i := 0; i < numberOfPeers; i++ {
		peer := &nbpeer.Peer{
			ID:        fmt.Sprintf("peer-%d", i),
			AccountID: accountID,
			Key:       fmt.Sprintf("key-%d", i),
			DNSLabel:  fmt.Sprintf("peer%d.example.com", i),
			IP:        intToIPv4(uint32(i)),
		}
		err = store.AddPeerToAccount(context.Background(), peer)
		if err != nil {
			b.Fatalf("Failed to add peer: %v", err)
		}
		peers = append(peers, peer)
	}

	for i := 0; i < numberOfGroups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &types.Group{
			ID:        groupID,
			AccountID: accountID,
		}
		err = store.CreateGroup(context.Background(), group)
		if err != nil {
			b.Fatalf("Failed to create group: %v", err)
		}
		for j := 0; j < numberOfPeersPerGroup; j++ {
			peerIndex := (i*numberOfPeersPerGroup + j) % numberOfPeers
			err = store.AddPeerToGroup(context.Background(), accountID, peers[peerIndex].ID, groupID)
			if err != nil {
				b.Fatalf("Failed to add peer to group: %v", err)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peers[i%numberOfPeers].ID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func intToIPv4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

func TestSqlStore_GetUserIDByPeerKey(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "test-user-123"
	peerKey := "peer-key-abc"

	peer := &nbpeer.Peer{
		ID:        "test-peer-1",
		Key:       peerKey,
		AccountID: existingAccountID,
		UserID:    userID,
		IP:        netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		IPv6:      netip.MustParseAddr("fd00::a00:1"),
		DNSLabel:  "test-peer-1",
	}

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err)

	retrievedUserID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, peerKey)
	require.NoError(t, err)
	assert.Equal(t, userID, retrievedUserID)
}

func TestSqlStore_GetUserIDByPeerKey_NotFound(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	nonExistentPeerKey := "non-existent-peer-key"

	userID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, nonExistentPeerKey)
	require.Error(t, err)
	assert.Equal(t, "", userID)
}

func TestSqlStore_GetUserIDByPeerKey_NoUserID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerKey := "peer-key-abc"

	peer := &nbpeer.Peer{
		ID:        "test-peer-1",
		Key:       peerKey,
		AccountID: existingAccountID,
		UserID:    "",
		IP:        netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		IPv6:      netip.MustParseAddr("fd00::a00:1"),
		DNSLabel:  "test-peer-1",
	}

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err)

	retrievedUserID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, peerKey)
	require.NoError(t, err)
	assert.Equal(t, "", retrievedUserID)
}

func TestSqlStore_ApproveAccountPeers(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		accountID := "test-account"
		ctx := context.Background()

		account := newAccountWithId(ctx, accountID, "testuser", "example.com")
		err := store.SaveAccount(ctx, account)
		require.NoError(t, err)

		peers := []*nbpeer.Peer{
			{
				ID:        "peer1",
				AccountID: accountID,
				DNSLabel:  "peer1.netbird.cloud",
				Key:       "peer1-key",
				IP:        netip.MustParseAddr("100.64.0.1"),
				IPv6:      netip.MustParseAddr("fd00::1"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: true,
					LastSeen:         time.Now().UTC(),
				},
			},
			{
				ID:        "peer2",
				AccountID: accountID,
				DNSLabel:  "peer2.netbird.cloud",
				Key:       "peer2-key",
				IP:        netip.MustParseAddr("100.64.0.2"),
				IPv6:      netip.MustParseAddr("fd00::2"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: true,
					LastSeen:         time.Now().UTC(),
				},
			},
			{
				ID:        "peer3",
				AccountID: accountID,
				DNSLabel:  "peer3.netbird.cloud",
				Key:       "peer3-key",
				IP:        netip.MustParseAddr("100.64.0.3"),
				IPv6:      netip.MustParseAddr("fd00::3"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: false,
					LastSeen:         time.Now().UTC(),
				},
			},
		}

		for _, peer := range peers {
			err = store.AddPeerToAccount(ctx, peer)
			require.NoError(t, err)
		}

		t.Run("approve all pending peers", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, accountID)
			require.NoError(t, err)
			assert.Equal(t, 2, count)

			allPeers, err := store.GetAccountPeers(ctx, LockingStrengthNone, accountID, "", "")
			require.NoError(t, err)

			for _, peer := range allPeers {
				assert.False(t, peer.Status.RequiresApproval, "peer %s should not require approval", peer.ID)
			}
		})

		t.Run("no peers to approve", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, accountID)
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})

		t.Run("non-existent account", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, "non-existent")
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})
	})
}
