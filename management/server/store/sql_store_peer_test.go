package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
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
		assert.Equal(t, 34, numOfFields)

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
	storedLastSeen := time.Now().UTC().Add(-time.Hour)
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		ID:     "testpeer",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{LastSeen: storedLastSeen},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	newStatus.LoginExpired = true
	newStatus.RequiresApproval = true
	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.True(t, actual.LoginExpired)
	assert.True(t, actual.RequiresApproval)
	assert.WithinDurationf(t, storedLastSeen, actual.LastSeen.UTC(), time.Millisecond, "LastSeen is not written by SavePeerStatus")

	newStatus.LoginExpired = false
	newStatus.RequiresApproval = false
	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual = account.Peers["testpeer"].Status
	assert.False(t, actual.LoginExpired)
	assert.False(t, actual.RequiresApproval)
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

	require.NoError(t, store.RegisterInstance(context.Background(), "instance-1", "host"))
	applied, err := store.ConnectPeer(context.Background(), accountID, peer.ID, "instance-1", 1)
	require.NoError(t, err)
	require.True(t, applied)

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
	assert.Equal(t, int64(1), storedPeer.Status.SessionStartedAt)
	assert.Equal(t, peer.Status.LoginExpired, storedPeer.Status.LoginExpired)
	assert.Equal(t, peer.Status.RequiresApproval, storedPeer.Status.RequiresApproval)
	assert.WithinDurationf(t, time.Now().UTC(), storedPeer.Status.LastSeen.UTC(), time.Minute, "LastSeen should follow the connection")
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
			peers, _, err := store.GetAccountPeersPaginated(context.Background(), LockingStrengthNone, tt.accountID, PaginationState{}, PeerFilters{Hostname: tt.nameFilter, IP: tt.ipFilter}, PeerSorting{})
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetAccountPeers_FilterByMac(t *testing.T) {
	ctx := context.Background()
	store, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	accountID := "test-account-mac"
	userID := "test-user-mac"
	account := newAccountWithId(ctx, accountID, userID, "example.com")
	account.Peers["peer-mac-1"] = &nbpeer.Peer{
		ID:        "peer-mac-1",
		AccountID: accountID,
		Key:       "peer-mac-key-1",
		Name:      "macpeer",
		IP:        netip.MustParseAddr("100.64.0.10"),
		Meta: nbpeer.PeerSystemMeta{
			NetworkAddresses: []nbpeer.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.0.11/24"), Mac: "00:93:37:bd:83:0f"},
			},
		},
	}
	require.NoError(t, store.SaveAccount(ctx, account))

	tests := []struct {
		name          string
		macFilter     string
		expectedCount int
	}{
		{name: "full mac matches", macFilter: "00:93:37:bd:83:0f", expectedCount: 1},
		{name: "mac prefix matches", macFilter: "00:93:37", expectedCount: 1},
		{name: "unknown mac does not match", macFilter: "11:22:33:44:55:66", expectedCount: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, _, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, accountID, PaginationState{}, PeerFilters{MAC: tt.macFilter}, PeerSorting{})
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

			allPeers, err := store.GetAccountPeers(ctx, LockingStrengthNone, accountID, "", "", "")
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

const peerConnectionAccountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

func addPeerConnectionTestPeers(t *testing.T, store Store, ids ...string) {
	t.Helper()
	for i, id := range ids {
		require.NoError(t, store.AddPeerToAccount(context.Background(), &nbpeer.Peer{
			ID:        id,
			AccountID: peerConnectionAccountID,
			Key:       "key-" + id,
			DNSLabel:  id,
			IP:        netip.AddrFrom4([4]byte{10, 9, 2, byte(i + 1)}),
			IPv6:      netip.MustParseAddr(fmt.Sprintf("fd00::9:2:%d", i+1)),
			Status:    &nbpeer.PeerStatus{},
		}))
		setPeerLastSeen(t, store, id, time.Now().UTC().Add(-2*time.Hour))
	}
}

func addBulkPeers(t *testing.T, store Store, prefix string, count int) {
	t.Helper()
	peers := make([]*nbpeer.Peer, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%s%d", prefix, i)
		peers = append(peers, &nbpeer.Peer{
			ID:        id,
			AccountID: peerConnectionAccountID,
			Key:       "key-" + id,
			DNSLabel:  id,
			IP:        netip.AddrFrom4([4]byte{10, 8, byte(i >> 8), byte(i)}),
			IPv6:      netip.MustParseAddr(fmt.Sprintf("fd00::8:%x", i)),
			Status:    &nbpeer.PeerStatus{},
		})
	}
	require.NoError(t, store.(*SqlStore).db.CreateInBatches(peers, 200).Error)
}

func setPeerLastSeen(t *testing.T, store Store, peerID string, lastSeen any) {
	t.Helper()
	require.NoError(t, store.(*SqlStore).db.Model(&nbpeer.Connection{}).Where("peer_id = ?", peerID).
		Update("last_seen", lastSeen).Error)
}

// peerLastSeen reads the stored column of the connection record, not the effective LastSeen
// of the loaded peer. It returns the zero time when the column is NULL.
func peerLastSeen(t *testing.T, store Store, peerID string) time.Time {
	t.Helper()
	var lastSeen sql.NullTime
	require.NoError(t, store.(*SqlStore).db.Model(&nbpeer.Connection{}).Where("peer_id = ?", peerID).
		Select("last_seen").Row().Scan(&lastSeen))
	return lastSeen.Time.UTC()
}

func ageInstance(t *testing.T, store Store, id string, age time.Duration) time.Time {
	t.Helper()
	lastSeen := time.Now().UTC().Add(-age)
	require.NoError(t, store.(*SqlStore).db.Model(&nbpeer.ManagementInstance{}).Where("id = ?", id).
		Update("last_seen", lastSeen).Error)
	return lastSeen
}

func getPeerConnection(t *testing.T, store Store, peerID string) *nbpeer.Connection {
	t.Helper()
	var rows []nbpeer.Connection
	require.NoError(t, store.(*SqlStore).db.Where("peer_id = ?", peerID).Find(&rows).Error)
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

// instanceOf returns the instance holding the connection, empty when none does.
func instanceOf(conn *nbpeer.Connection) string {
	if conn == nil || conn.InstanceID == nil {
		return ""
	}
	return *conn.InstanceID
}

func countPeerConnections(t *testing.T, store Store, instanceID string) int64 {
	t.Helper()
	var count int64
	require.NoError(t, store.(*SqlStore).db.Model(&nbpeer.Connection{}).Where("instance_id = ?", instanceID).Count(&count).Error)
	return count
}

// peersRow reads the whole stored row of a peer, whatever columns the schema has.
func peersRow(t *testing.T, store Store, peerID string) map[string]any {
	t.Helper()
	row := map[string]any{}
	require.NoError(t, store.(*SqlStore).db.Table("peers").Where("id = ?", peerID).Take(&row).Error)
	return row
}

func TestSqlStore_AddPeerToAccountCreatesConnection(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		registered := time.Now().UTC().Add(-time.Hour)
		newPeer := func(id string, status *nbpeer.PeerStatus) *nbpeer.Peer {
			return &nbpeer.Peer{
				ID: id, AccountID: peerConnectionAccountID, Key: "key-" + id, DNSLabel: id, Status: status,
				IP:   netip.AddrFrom4([4]byte{10, 9, 3, byte(len(id))}),
				IPv6: netip.MustParseAddr(fmt.Sprintf("fd00::9:3:%d", len(id))),
			}
		}

		require.NoError(t, store.AddPeerToAccount(ctx, newPeer("p1", &nbpeer.PeerStatus{LastSeen: registered})))
		conn := getPeerConnection(t, store, "p1")
		require.NotNil(t, conn, "a new peer gets its connection record")
		assert.Equal(t, peerConnectionAccountID, conn.AccountID)
		assert.Empty(t, instanceOf(conn))
		assert.Zero(t, conn.SessionStartedAt)
		assert.WithinDuration(t, registered, peerLastSeen(t, store, "p1"), time.Second, "last seen is the registration time")

		require.NoError(t, store.AddPeerToAccount(ctx, newPeer("p22", nil)))
		require.NotNil(t, getPeerConnection(t, store, "p22"))
		assert.True(t, peerLastSeen(t, store, "p22").IsZero(), "a peer without a status was never seen")

		peer, err := store.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "p1")
		require.NoError(t, err)
		assert.False(t, peer.Status.Connected)
		assert.WithinDuration(t, registered, peer.Status.LastSeen.UTC(), time.Second)

		require.Error(t, store.AddPeerToAccount(ctx, newPeer("p1", nil)), "a duplicate peer is rejected")
	})
}

func TestSqlStore_ConnectPeerFencing(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		old := time.Now().UTC().Add(-2 * time.Hour)

		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		assert.True(t, applied, "first connect applies")
		conn := getPeerConnection(t, store, "peer-a")
		assert.Equal(t, "inst-1", instanceOf(conn))
		assert.Equal(t, int64(100), conn.SessionStartedAt)
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute, "an applied connect stamps last seen")

		for name, session := range map[string]int64{"equal session": 100, "older session": 50} {
			setPeerLastSeen(t, store, "peer-a", old)
			applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-2", session)
			require.NoError(t, err, name)
			assert.False(t, applied, name)
			assert.Equal(t, "inst-1", instanceOf(getPeerConnection(t, store, "peer-a")), name)
			assert.Equal(t, int64(100), getPeerConnection(t, store, "peer-a").SessionStartedAt, name)
			assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-a"), time.Second, "%s must not stamp last seen", name)
		}

		applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-2", 200)
		require.NoError(t, err)
		assert.True(t, applied, "a newer session takes the peer over")
		conn = getPeerConnection(t, store, "peer-a")
		assert.Equal(t, "inst-2", instanceOf(conn))
		assert.Equal(t, int64(200), conn.SessionStartedAt)
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute)

		applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-new", "inst-2", 1)
		require.NoError(t, err)
		assert.False(t, applied, "a peer that does not exist cannot be connected")
		assert.Nil(t, getPeerConnection(t, store, "peer-new"), "and gets no orphan record")

		require.NoError(t, store.(*SqlStore).db.Delete(&nbpeer.Connection{}, "peer_id = ?", "peer-a").Error)
		applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-3", 1)
		require.NoError(t, err)
		assert.True(t, applied, "an existing peer without a record gets one")
		assert.Equal(t, "inst-3", instanceOf(getPeerConnection(t, store, "peer-a")))
	})
}

func TestSqlStore_ConnectPeerAfterRelease(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")

		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		released, err := store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 100)
		require.NoError(t, err)
		require.True(t, released)

		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		assert.False(t, applied, "the released session cannot come back")
		applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-2", 102)
		require.NoError(t, err)
		assert.True(t, applied, "a newer session connects the released peer")
		assert.Equal(t, "inst-2", instanceOf(getPeerConnection(t, store, "peer-a")))
	})
}

func TestSqlStore_DisconnectPeerFencing(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		old := time.Now().UTC().Add(-2 * time.Hour)

		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		require.True(t, applied)
		setPeerLastSeen(t, store, "peer-a", old)

		released, err := store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 99)
		require.NoError(t, err)
		assert.False(t, released, "a session that does not hold the connection cannot release it")
		assert.Equal(t, "inst-1", instanceOf(getPeerConnection(t, store, "peer-a")))
		assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-a"), time.Second)

		released, err = store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 100)
		require.NoError(t, err)
		assert.True(t, released)
		conn := getPeerConnection(t, store, "peer-a")
		require.NotNil(t, conn, "the record stays")
		assert.Empty(t, instanceOf(conn))
		assert.Equal(t, int64(101), conn.SessionStartedAt, "the session token advances past the released session")
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute, "a disconnect stamps last seen")

		setPeerLastSeen(t, store, "peer-a", old)
		released, err = store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 100)
		require.NoError(t, err)
		assert.False(t, released, "a second disconnect of the ended session matches nothing")
		assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-a"), time.Second, "and leaves last seen alone")

		released, err = store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-gone", 100)
		require.NoError(t, err)
		assert.False(t, released, "a peer that no longer exists is not an error")

		applied, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 200)
		require.NoError(t, err)
		require.True(t, applied)
		released, err = store.DisconnectPeer(ctx, "other-account", "peer-a", 200)
		require.NoError(t, err)
		assert.False(t, released, "a disconnect scoped to another account leaves the connection")
		assert.Equal(t, "inst-1", instanceOf(getPeerConnection(t, store, "peer-a")))
	})
}

func TestSqlStore_DisconnectPeerAfterSweep(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "one"))
		instanceSeen := ageInstance(t, store, "inst-1", nbpeer.StaleAfter+time.Minute)
		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		swept, err := store.SweepInstanceChunk(ctx, "inst-1", instanceSeen, 10)
		require.NoError(t, err)
		require.Equal(t, 1, swept)
		require.Empty(t, instanceOf(getPeerConnection(t, store, "peer-a")))
		setPeerLastSeen(t, store, "peer-a", instanceSeen)

		released, err := store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 100)
		require.NoError(t, err)
		assert.True(t, released, "the ended stream still disconnects a row that was swept")
		conn := getPeerConnection(t, store, "peer-a")
		assert.Equal(t, int64(101), conn.SessionStartedAt)
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute, "last seen is raised")

		require.NoError(t, store.ReRegisterPeers(ctx, "inst-2", []types.PeerSession{
			{AccountID: peerConnectionAccountID, PeerID: "peer-a", SessionStartedAt: 100},
		}))
		assert.Empty(t, instanceOf(getPeerConnection(t, store, "peer-a")), "the ended session is not reclaimed")

		future := time.Now().UTC().Add(time.Hour)
		setPeerLastSeen(t, store, "peer-a", future)
		released, err = store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 101)
		require.NoError(t, err)
		assert.True(t, released)
		assert.WithinDuration(t, future, peerLastSeen(t, store, "peer-a"), time.Second, "last seen never moves backwards")
	})
}

func TestSqlStore_ReleasePeerConnection(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b", "peer-c")
		for _, id := range []string{"peer-a", "peer-b"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, id, "inst-1", 100)
			require.NoError(t, err)
		}
		old := time.Now().UTC().Add(-2 * time.Hour)
		for _, id := range []string{"peer-a", "peer-b", "peer-c"} {
			setPeerLastSeen(t, store, id, old)
		}

		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-a"))
		conn := getPeerConnection(t, store, "peer-a")
		require.NotNil(t, conn, "the record stays")
		assert.Empty(t, instanceOf(conn), "the session is released whatever its token")
		assert.Equal(t, int64(101), conn.SessionStartedAt, "the released session no longer matches its own token")
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute, "a held connection is stamped")
		assert.Equal(t, "inst-1", instanceOf(getPeerConnection(t, store, "peer-b")))

		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-c"))
		assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-c"), time.Second, "a peer no instance held keeps its last seen")
		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-gone"), "releasing a missing record is not an error")
	})
}

func TestSqlStore_RegisterAndHeartbeatInstance(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		getInstance := func(id string) *nbpeer.ManagementInstance {
			var rows []nbpeer.ManagementInstance
			require.NoError(t, store.(*SqlStore).db.Where("id = ?", id).Find(&rows).Error)
			if len(rows) == 0 {
				return nil
			}
			return &rows[0]
		}

		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "host-a"))
		got := getInstance("inst-1")
		require.NotNil(t, got)
		assert.Equal(t, "host-a", got.Hostname)
		assert.WithinDuration(t, time.Now().UTC(), got.StartedAt.UTC(), time.Minute)
		assert.WithinDuration(t, time.Now().UTC(), got.LastSeen.UTC(), time.Minute)

		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "host-b"))
		assert.Equal(t, "host-b", getInstance("inst-1").Hostname, "registering an existing id updates it")

		ageInstance(t, store, "inst-1", time.Minute)
		alive, err := store.HeartbeatInstance(ctx, "inst-1")
		require.NoError(t, err)
		assert.True(t, alive, "a fresh row heartbeats")
		assert.WithinDuration(t, time.Now().UTC(), getInstance("inst-1").LastSeen.UTC(), 10*time.Second)

		stale := ageInstance(t, store, "inst-1", nbpeer.StaleAfter+time.Minute)
		alive, err = store.HeartbeatInstance(ctx, "inst-1")
		require.NoError(t, err)
		assert.False(t, alive, "a stale row must not be revived")
		assert.WithinDuration(t, stale, getInstance("inst-1").LastSeen.UTC(), time.Second)

		alive, err = store.HeartbeatInstance(ctx, "inst-missing")
		require.NoError(t, err)
		assert.False(t, alive, "a missing row cannot heartbeat")
	})
}

func TestSqlStore_SweepInstanceChunk(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b", "peer-c", "peer-d")
		require.NoError(t, store.RegisterInstance(ctx, "inst-dead", "dead"))
		require.NoError(t, store.RegisterInstance(ctx, "inst-live", "live"))
		deadSeen := ageInstance(t, store, "inst-dead", nbpeer.StaleAfter+time.Minute)

		for peerID, instanceID := range map[string]string{"peer-a": "inst-dead", "peer-b": "inst-dead", "peer-c": "inst-dead", "peer-d": "inst-live"} {
			applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, instanceID, 100)
			require.NoError(t, err)
			require.True(t, applied)
		}
		old := time.Now().UTC().Add(-2 * time.Hour)
		newer := time.Now().UTC().Add(-time.Minute)
		setPeerLastSeen(t, store, "peer-a", old)
		setPeerLastSeen(t, store, "peer-b", newer)
		setPeerLastSeen(t, store, "peer-c", nil)
		setPeerLastSeen(t, store, "peer-d", old)

		stale, err := store.ListStaleInstances(ctx)
		require.NoError(t, err)
		require.Len(t, stale, 1, "only the aged instance is stale")
		assert.Equal(t, "inst-dead", stale[0].ID)
		assert.WithinDuration(t, deadSeen, stale[0].LastSeen.UTC(), time.Second)

		swept, err := store.SweepInstanceChunk(ctx, "inst-live", deadSeen, 10)
		require.NoError(t, err)
		assert.Zero(t, swept, "a fresh instance is never swept")
		assert.Equal(t, "inst-live", instanceOf(getPeerConnection(t, store, "peer-d")))
		assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-d"), time.Second)

		swept, err = store.SweepInstanceChunk(ctx, "inst-dead", deadSeen, 2)
		require.NoError(t, err)
		assert.Equal(t, 2, swept, "a chunk is bounded by the limit")
		assert.Equal(t, int64(1), countPeerConnections(t, store, "inst-dead"))

		swept, err = store.SweepInstanceChunk(ctx, "inst-dead", deadSeen, 2)
		require.NoError(t, err)
		assert.Equal(t, 1, swept)
		assert.Zero(t, countPeerConnections(t, store, "inst-dead"))
		for _, id := range []string{"peer-a", "peer-b", "peer-c"} {
			conn := getPeerConnection(t, store, id)
			require.NotNil(t, conn, "%s keeps its record", id)
			assert.Empty(t, instanceOf(conn), id)
			assert.Equal(t, int64(100), conn.SessionStartedAt, id)
		}

		assert.WithinDuration(t, deadSeen, peerLastSeen(t, store, "peer-a"), time.Second, "last seen rises to the instance's last heartbeat")
		assert.WithinDuration(t, newer, peerLastSeen(t, store, "peer-b"), time.Second, "last seen never moves backwards")
		assert.WithinDuration(t, deadSeen, peerLastSeen(t, store, "peer-c"), time.Second, "an unset last seen is filled")

		swept, err = store.SweepInstanceChunk(ctx, "inst-dead", deadSeen, 2)
		require.NoError(t, err)
		assert.Zero(t, swept, "a second sweep is a no-op")
		assert.WithinDuration(t, deadSeen, peerLastSeen(t, store, "peer-a"), time.Second)

		deleted, err := store.DeleteInstanceIfStale(ctx, "inst-live")
		require.NoError(t, err)
		assert.False(t, deleted, "a fresh instance row stays")
		deleted, err = store.DeleteInstanceIfStale(ctx, "inst-dead")
		require.NoError(t, err)
		assert.True(t, deleted)
		stale, err = store.ListStaleInstances(ctx)
		require.NoError(t, err)
		assert.Empty(t, stale)
	})
}

func TestSqlStore_SweepOrphanedInstance(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b", "peer-c", "peer-d")
		require.NoError(t, store.RegisterInstance(ctx, "inst-live", "live"))
		for peerID, instanceID := range map[string]string{"peer-a": "inst-ghost", "peer-b": "inst-ghost", "peer-c": "inst-live", "peer-d": "inst-ghost"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, instanceID, 100)
			require.NoError(t, err)
		}
		old := time.Now().UTC().Add(-2 * time.Hour)
		setPeerLastSeen(t, store, "peer-a", old)
		setPeerLastSeen(t, store, "peer-b", nil)
		future := time.Now().UTC().Add(time.Hour)
		setPeerLastSeen(t, store, "peer-d", future)

		stale, err := store.ListStaleInstances(ctx)
		require.NoError(t, err)
		require.Len(t, stale, 1, "an instance ID with connections and no instance row is listed once")
		assert.Equal(t, "inst-ghost", stale[0].ID)
		assert.True(t, stale[0].LastSeen.IsZero())

		swept, err := store.SweepInstanceChunk(ctx, "inst-ghost", stale[0].LastSeen, 10)
		require.NoError(t, err)
		assert.Equal(t, 3, swept)
		assert.Zero(t, countPeerConnections(t, store, "inst-ghost"))
		assert.Equal(t, "inst-live", instanceOf(getPeerConnection(t, store, "peer-c")))

		now := time.Now().UTC()
		assert.WithinDuration(t, now, peerLastSeen(t, store, "peer-a"), time.Minute, "an orphan's peers are stamped with the database clock")
		assert.WithinDuration(t, now, peerLastSeen(t, store, "peer-b"), time.Minute, "an unset last seen is filled")
		assert.WithinDuration(t, future, peerLastSeen(t, store, "peer-d"), time.Second, "last seen never moves backwards")

		stale, err = store.ListStaleInstances(ctx)
		require.NoError(t, err)
		assert.Empty(t, stale)
	})
}

func TestSqlStore_ListStaleInstancesOrphans(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		peerIDs := []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-e", "peer-f", "peer-g"}
		addPeerConnectionTestPeers(t, store, peerIDs...)
		require.NoError(t, store.RegisterInstance(ctx, "inst-b", "live"))

		stale, err := store.ListStaleInstances(ctx)
		require.NoError(t, err)
		assert.Empty(t, stale, "records without an instance are not orphans")

		holders := map[string]string{
			"peer-a": "inst-a", "peer-b": "inst-b", "peer-c": "inst-a", "peer-d": "inst-c", "peer-e": "inst-d", "peer-f": "inst-d",
		}
		for peerID, instanceID := range holders {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, instanceID, 100)
			require.NoError(t, err)
		}

		stale, err = store.ListStaleInstances(ctx)
		require.NoError(t, err)
		ids := make([]string, 0, len(stale))
		for _, instance := range stale {
			assert.True(t, instance.LastSeen.IsZero(), instance.ID)
			ids = append(ids, instance.ID)
		}
		assert.ElementsMatch(t, []string{"inst-a", "inst-c", "inst-d"}, ids, "each orphan is listed once and the live instance is not")
	})
}

func TestSqlStore_SweepInstanceChunkKeepsRowsThatMoved(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b")
		require.NoError(t, store.RegisterInstance(ctx, "inst-dead", "dead"))
		require.NoError(t, store.RegisterInstance(ctx, "inst-live", "live"))
		deadSeen := ageInstance(t, store, "inst-dead", nbpeer.StaleAfter+time.Minute)
		for _, id := range []string{"peer-a", "peer-b"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, id, "inst-dead", 100)
			require.NoError(t, err)
		}

		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-live", 200)
		require.NoError(t, err)
		require.True(t, applied)

		swept, err := store.SweepInstanceChunk(ctx, "inst-dead", deadSeen, 10)
		require.NoError(t, err)
		assert.Equal(t, 1, swept)
		moved := getPeerConnection(t, store, "peer-a")
		require.NotNil(t, moved)
		assert.Equal(t, "inst-live", instanceOf(moved), "a connection that moved to a live instance survives")
		assert.Empty(t, instanceOf(getPeerConnection(t, store, "peer-b")))
		assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, "peer-a"), time.Minute, "the swept instance does not touch a moved peer's last seen")
	})
}

func TestSqlStore_ReleaseInstance(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b", "peer-c")
		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "one"))
		require.NoError(t, store.RegisterInstance(ctx, "inst-2", "two"))
		for peerID, instanceID := range map[string]string{"peer-a": "inst-1", "peer-b": "inst-1", "peer-c": "inst-2"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, instanceID, 100)
			require.NoError(t, err)
		}
		old := time.Now().UTC().Add(-2 * time.Hour)
		for _, id := range []string{"peer-a", "peer-b", "peer-c"} {
			setPeerLastSeen(t, store, id, old)
		}

		require.NoError(t, store.ReleaseInstance(ctx, "inst-1"))

		assert.Zero(t, countPeerConnections(t, store, "inst-1"))
		assert.Equal(t, int64(1), countPeerConnections(t, store, "inst-2"))
		for _, id := range []string{"peer-a", "peer-b"} {
			conn := getPeerConnection(t, store, id)
			require.NotNil(t, conn, "%s keeps its record", id)
			assert.Empty(t, instanceOf(conn), id)
			assert.WithinDuration(t, time.Now().UTC(), peerLastSeen(t, store, id), time.Minute, id)
		}
		assert.WithinDuration(t, old, peerLastSeen(t, store, "peer-c"), time.Second, "peers of other instances are untouched")

		var ids []string
		require.NoError(t, store.(*SqlStore).db.Model(&nbpeer.ManagementInstance{}).Order("id").Pluck("id", &ids).Error)
		assert.Equal(t, []string{"inst-2"}, ids)
	})
}

func TestSqlStore_ReRegisterPeers(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b", "peer-c")
		require.NoError(t, store.(*SqlStore).db.Delete(&nbpeer.Connection{}, "peer_id = ?", "peer-c").Error)
		addBulkPeers(t, store, "bulk-", peerConnectionChunkSize+5)
		for peerID, session := range map[string]int64{"peer-a": 100, "peer-b": 200} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, "inst-old", session)
			require.NoError(t, err)
		}

		sessions := []types.PeerSession{
			{AccountID: peerConnectionAccountID, PeerID: "peer-a", SessionStartedAt: 100},
			{AccountID: peerConnectionAccountID, PeerID: "peer-b", SessionStartedAt: 150},
			{AccountID: peerConnectionAccountID, PeerID: "peer-c", SessionStartedAt: 300},
			{AccountID: peerConnectionAccountID, PeerID: "peer-gone", SessionStartedAt: 300},
		}
		for i := 0; i < peerConnectionChunkSize+5; i++ {
			sessions = append(sessions, types.PeerSession{AccountID: peerConnectionAccountID, PeerID: fmt.Sprintf("bulk-%d", i), SessionStartedAt: 1})
		}

		require.NoError(t, store.ReRegisterPeers(ctx, "inst-new", sessions))

		a := getPeerConnection(t, store, "peer-a")
		assert.Equal(t, "inst-new", instanceOf(a), "an equal session is re-pointed")
		assert.Equal(t, int64(100), a.SessionStartedAt)
		b := getPeerConnection(t, store, "peer-b")
		assert.Equal(t, "inst-old", instanceOf(b), "an older session never overwrites a newer record")
		assert.Equal(t, int64(200), b.SessionStartedAt)
		c := getPeerConnection(t, store, "peer-c")
		require.NotNil(t, c, "a missing record of an existing peer is inserted")
		assert.Equal(t, "inst-new", instanceOf(c))
		assert.Equal(t, int64(300), c.SessionStartedAt)
		assert.Nil(t, getPeerConnection(t, store, "peer-gone"), "a peer that does not exist gets no record")
		assert.Equal(t, int64(2+peerConnectionChunkSize+5), countPeerConnections(t, store, "inst-new"), "every chunk is written")

		require.NoError(t, store.ReRegisterPeers(ctx, "inst-new", nil))
	})
}

func TestPostgresTestStoreCopiesLivenessTables(t *testing.T) {
	if engine := os.Getenv("NETBIRD_STORE_ENGINE"); engine != "" && engine != string(types.PostgresStoreEngine) {
		t.Skip("exercises the copy into the postgres test store")
	}
	ctx := context.Background()

	conn, err := db.OpenSqliteFile(ctx, t.TempDir(), db.SqliteFileName)
	require.NoError(t, err)
	require.NoError(t, LoadSQL(conn.DB(nil), "../testdata/extended-store.sql"))
	sqliteStore, err := NewSqlStore(ctx, conn, nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqliteStore.Close(ctx) })

	addPeerConnectionTestPeers(t, sqliteStore, "peer-a", "peer-b")
	require.NoError(t, sqliteStore.RegisterInstance(ctx, "inst-live", "live"))
	applied, err := sqliteStore.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-live", 100)
	require.NoError(t, err)
	require.True(t, applied)

	pgStore, cleanup, err := newReusedPostgresStore(ctx, sqliteStore)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = pgStore.Close(ctx)
		cleanup()
	})

	a, err := pgStore.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "peer-a")
	require.NoError(t, err)
	assert.True(t, a.Status.Connected, "the instance and connection rows are copied")
	assert.Equal(t, int64(100), a.Status.SessionStartedAt)
	assert.WithinDuration(t, time.Now().UTC(), a.Status.LastSeen.UTC(), time.Minute)
	b, err := pgStore.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "peer-b")
	require.NoError(t, err)
	assert.False(t, b.Status.Connected)
	assert.Equal(t, "inst-live", instanceOf(getPeerConnection(t, pgStore, "peer-a")))
}

func TestSqlStore_ReRegisterPeersFailedChunk(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		total := 2*peerConnectionChunkSize + 5
		addBulkPeers(t, store, "bulk-", total)
		sessions := make([]types.PeerSession, 0, total)
		for i := 0; i < total; i++ {
			sessions = append(sessions, types.PeerSession{AccountID: peerConnectionAccountID, PeerID: fmt.Sprintf("bulk-%d", i), SessionStartedAt: 1})
		}

		var chunk int
		const callbackName = "test:fail_reregister_chunks"
		db := store.(*SqlStore).db
		require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register(callbackName, func(tx *gorm.DB) {
			if !strings.Contains(tx.Statement.SQL.String(), "INSERT INTO peer_connections") {
				return
			}
			chunk++
			if chunk == 1 || chunk == 3 {
				_ = tx.AddError(fmt.Errorf("injected failure of chunk %d", chunk))
			}
		}))
		t.Cleanup(func() { _ = db.Callback().Raw().Remove(callbackName) })

		err := store.ReRegisterPeers(ctx, "inst-new", sessions)
		require.Error(t, err)
		assert.ErrorContains(t, err, "injected failure of chunk 1")
		assert.ErrorContains(t, err, "injected failure of chunk 3", "the error joins every failed chunk")
		assert.Equal(t, 3, chunk, "a failed chunk does not stop the later ones")

		assert.Empty(t, instanceOf(getPeerConnection(t, store, "bulk-0")), "the first chunk is not applied")
		assert.Equal(t, "inst-new", instanceOf(getPeerConnection(t, store, fmt.Sprintf("bulk-%d", peerConnectionChunkSize))), "the second chunk is applied")
		assert.Empty(t, instanceOf(getPeerConnection(t, store, fmt.Sprintf("bulk-%d", total-1))), "the third chunk is not applied")
		assert.Equal(t, int64(peerConnectionChunkSize), countPeerConnections(t, store, "inst-new"))
	})
}

func TestSqlStore_ReRegisterPeersCancelledContext(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		addBulkPeers(t, store, "bulk-", peerConnectionChunkSize+5)
		sessions := make([]types.PeerSession, 0, peerConnectionChunkSize+5)
		for i := 0; i < peerConnectionChunkSize+5; i++ {
			sessions = append(sessions, types.PeerSession{AccountID: peerConnectionAccountID, PeerID: fmt.Sprintf("bulk-%d", i), SessionStartedAt: 1})
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := store.ReRegisterPeers(ctx, "inst-new", sessions)
		require.Error(t, err)
		assert.ErrorContains(t, err, context.Canceled.Error())
		assert.Zero(t, countPeerConnections(t, store, "inst-new"), "a done context writes nothing")
	})
}

func TestSqlStore_ConnectPeerRequiresMatchingAccount(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")

		applied, err := store.ConnectPeer(ctx, "other-account", "peer-a", "inst-1", 100)
		require.NoError(t, err)
		assert.False(t, applied, "a session naming another account cannot connect the peer")
		assert.Empty(t, instanceOf(getPeerConnection(t, store, "peer-a")))

		require.NoError(t, store.ReRegisterPeers(ctx, "inst-1", []types.PeerSession{
			{AccountID: "other-account", PeerID: "peer-a", SessionStartedAt: 100},
		}))
		assert.Empty(t, instanceOf(getPeerConnection(t, store, "peer-a")), "nor can a re-registration")
	})
}

func TestSqlStore_SaveAccountDropsOrphanedConnections(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b")
		for _, id := range []string{"peer-a", "peer-b"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, id, "inst-1", 100)
			require.NoError(t, err)
		}

		account, err := store.GetAccount(ctx, peerConnectionAccountID)
		require.NoError(t, err)
		delete(account.Peers, "peer-b")
		require.NoError(t, store.SaveAccount(ctx, account))

		assert.Equal(t, "inst-1", instanceOf(getPeerConnection(t, store, "peer-a")), "a saved peer keeps its record")
		assert.Nil(t, getPeerConnection(t, store, "peer-b"), "a peer that is no longer saved loses its record")
	})
}

func TestSqlStore_ReRegisterPeersReclaimsSweptButNotReleased(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-swept", "peer-expired", "peer-expired-newer")
		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "one"))
		lastSeen := ageInstance(t, store, "inst-1", nbpeer.StaleAfter+time.Minute)
		for _, id := range []string{"peer-swept", "peer-expired", "peer-expired-newer"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, id, "inst-1", 100)
			require.NoError(t, err)
		}

		swept, err := store.SweepInstanceChunk(ctx, "inst-1", lastSeen, 10)
		require.NoError(t, err)
		require.Equal(t, 3, swept)
		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-expired"))
		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-expired-newer"))

		require.NoError(t, store.ReRegisterPeers(ctx, "inst-2", []types.PeerSession{
			{AccountID: peerConnectionAccountID, PeerID: "peer-swept", SessionStartedAt: 100},
			{AccountID: peerConnectionAccountID, PeerID: "peer-expired", SessionStartedAt: 100},
		}))
		assert.Equal(t, "inst-2", instanceOf(getPeerConnection(t, store, "peer-swept")), "a swept connection is reclaimed by its own session")
		assert.Empty(t, instanceOf(getPeerConnection(t, store, "peer-expired")), "a released connection is not reclaimed by the released session")

		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-expired-newer", "inst-2", 100+1_000_000)
		require.NoError(t, err)
		assert.True(t, applied, "a later session still claims a released peer")
	})
}

func TestSqlStore_LivenessWritesLeavePeersRowAlone(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b")
		before := peersRow(t, store, "peer-a")
		require.NotEmpty(t, before)
		beforeOther := peersRow(t, store, "peer-b")
		unchanged := func(step string) {
			t.Helper()
			assert.Equal(t, before, peersRow(t, store, "peer-a"), "%s must not write the peers row", step)
			assert.Equal(t, beforeOther, peersRow(t, store, "peer-b"), "%s must not write the peers row", step)
		}

		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "one"))
		require.NoError(t, store.RegisterInstance(ctx, "inst-dead", "dead"))
		deadSeen := ageInstance(t, store, "inst-dead", nbpeer.StaleAfter+time.Minute)

		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		unchanged("ConnectPeer")
		_, err = store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-a", 100)
		require.NoError(t, err)
		unchanged("DisconnectPeer")
		_, err = store.RefreshPeerLastSeen(ctx, peerConnectionAccountID, "peer-a", time.Now().UTC().Add(time.Hour))
		require.NoError(t, err)
		unchanged("RefreshPeerLastSeen")
		_, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-dead", 200)
		require.NoError(t, err)
		_, err = store.SweepInstanceChunk(ctx, "inst-dead", deadSeen, 10)
		require.NoError(t, err)
		unchanged("SweepInstanceChunk")
		_, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 300)
		require.NoError(t, err)
		require.NoError(t, store.ReleasePeerConnection(ctx, "peer-a"))
		unchanged("ReleasePeerConnection")
		require.NoError(t, store.ReRegisterPeers(ctx, "inst-1", []types.PeerSession{{AccountID: peerConnectionAccountID, PeerID: "peer-a", SessionStartedAt: 300}}))
		unchanged("ReRegisterPeers")
		require.NoError(t, store.ReleaseInstance(ctx, "inst-1"))
		unchanged("ReleaseInstance")
	})
}

func TestSqlStore_DeletePeerRemovesConnection(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a", "peer-b")
		for _, id := range []string{"peer-a", "peer-b"} {
			_, err := store.ConnectPeer(ctx, peerConnectionAccountID, id, "inst-1", 100)
			require.NoError(t, err)
		}

		require.NoError(t, store.DeletePeer(ctx, peerConnectionAccountID, "peer-a"))

		assert.Nil(t, getPeerConnection(t, store, "peer-a"))
		assert.NotNil(t, getPeerConnection(t, store, "peer-b"))
		assert.Error(t, store.DeletePeer(ctx, peerConnectionAccountID, "peer-a"), "a missing peer is still reported")
	})
}

func TestSqlStore_DeletePeerWithWrongAccountKeepsConnection(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)

		require.Error(t, store.DeletePeer(ctx, "other-account", "peer-a"))

		conn := getPeerConnection(t, store, "peer-a")
		require.NotNil(t, conn, "a delete scoped to another account keeps the record")
		assert.Equal(t, "inst-1", instanceOf(conn))
		_, err = store.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "peer-a")
		require.NoError(t, err)
	})
}

func TestSqlStore_DeleteAccountRemovesConnections(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 100)
		require.NoError(t, err)
		require.NoError(t, store.(*SqlStore).db.Exec("INSERT INTO accounts (id) VALUES ('other-account')").Error)
		require.NoError(t, store.(*SqlStore).db.Create(&nbpeer.Peer{ID: "other-peer", AccountID: "other-account", Status: &nbpeer.PeerStatus{}}).Error)
		_, err = store.ConnectPeer(ctx, "other-account", "other-peer", "inst-1", 100)
		require.NoError(t, err)

		account, err := store.GetAccount(ctx, peerConnectionAccountID)
		require.NoError(t, err)
		require.NoError(t, store.DeleteAccount(ctx, account))

		assert.Nil(t, getPeerConnection(t, store, "peer-a"))
		assert.NotNil(t, getPeerConnection(t, store, "other-peer"), "other accounts keep their rows")
	})
}

var peerConnectionStateIDs = []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-e"}

// seedPeerConnectionStates creates peers in five connection states and returns the
// expected effective LastSeen of each: a is held by a live instance, b by a stale one, c
// by none, d by an instance that is gone and e has no connection record at all.
func seedPeerConnectionStates(t *testing.T, store Store) map[string]time.Time {
	t.Helper()
	ctx := context.Background()
	addPeerConnectionTestPeers(t, store, peerConnectionStateIDs...)
	require.NoError(t, store.RegisterInstance(ctx, "inst-live", "live"))
	require.NoError(t, store.RegisterInstance(ctx, "inst-stale", "stale"))
	liveSeen := ageInstance(t, store, "inst-live", time.Minute)
	staleSeen := ageInstance(t, store, "inst-stale", nbpeer.StaleAfter+time.Minute)

	for peerID, session := range map[string]int64{"peer-a": 100, "peer-b": 200} {
		instance := map[string]string{"peer-a": "inst-live", "peer-b": "inst-stale"}[peerID]
		applied, err := store.ConnectPeer(ctx, peerConnectionAccountID, peerID, instance, session)
		require.NoError(t, err)
		require.True(t, applied)
	}
	_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-d", "inst-gone", 300)
	require.NoError(t, err)
	_, err = store.ConnectPeer(ctx, peerConnectionAccountID, "peer-c", "inst-live", 400)
	require.NoError(t, err)
	released, err := store.DisconnectPeer(ctx, peerConnectionAccountID, "peer-c", 400)
	require.NoError(t, err)
	require.True(t, released)

	own := time.Now().UTC().Add(-2 * time.Hour)
	for _, id := range []string{"peer-a", "peer-b", "peer-c", "peer-d"} {
		setPeerLastSeen(t, store, id, own)
	}
	require.NoError(t, store.(*SqlStore).db.Delete(&nbpeer.Connection{}, "peer_id = ?", "peer-e").Error)
	return map[string]time.Time{"peer-a": liveSeen, "peer-b": staleSeen, "peer-c": own, "peer-d": own, "peer-e": {}}
}

var peerConnectionStateWant = map[string]struct {
	connected bool
	session   int64
}{
	"peer-a": {connected: true, session: 100},
	"peer-b": {session: 200},
	"peer-c": {session: 401},
	"peer-d": {session: 300},
	"peer-e": {},
}

func assertPeerConnectionState(t *testing.T, name string, wantLen int, peers []*nbpeer.Peer, lastSeen map[string]time.Time) {
	t.Helper()
	got := 0
	for _, peer := range peers {
		want, ok := peerConnectionStateWant[peer.ID]
		if !ok {
			continue
		}
		got++
		require.NotNil(t, peer.Status, "%s %s", name, peer.ID)
		assert.Equal(t, want.connected, peer.Status.Connected, "%s %s connected", name, peer.ID)
		assert.Equal(t, want.session, peer.Status.SessionStartedAt, "%s %s session", name, peer.ID)
		assert.WithinDuration(t, lastSeen[peer.ID], peer.Status.LastSeen.UTC(), time.Second, "%s %s last seen", name, peer.ID)
	}
	assert.Equal(t, wantLen, got, "%s returns the seeded peers", name)
}

func TestSqlStore_PeerStatusFromConnections(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		lastSeen := seedPeerConnectionStates(t, store)
		sqlStore := store.(*SqlStore)
		ids := peerConnectionStateIDs

		for i, id := range ids {
			byID, err := store.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, id)
			require.NoError(t, err)
			byKey, err := store.GetPeerByPeerPubKey(ctx, LockingStrengthNone, "key-"+id)
			require.NoError(t, err)
			byIP, err := store.GetPeerByIP(ctx, LockingStrengthNone, peerConnectionAccountID, net.IPv4(10, 9, 2, byte(i+1)))
			require.NoError(t, err)
			assertPeerConnectionState(t, "GetPeerByID", 1, []*nbpeer.Peer{byID}, lastSeen)
			assertPeerConnectionState(t, "GetPeerByPeerPubKey", 1, []*nbpeer.Peer{byKey}, lastSeen)
			assertPeerConnectionState(t, "GetPeerByIP", 1, []*nbpeer.Peer{byIP}, lastSeen)
		}

		byIDs, err := store.GetPeersByIDs(ctx, LockingStrengthNone, peerConnectionAccountID, ids)
		require.NoError(t, err)
		list := make([]*nbpeer.Peer, 0, len(byIDs))
		for _, peer := range byIDs {
			list = append(list, peer)
		}
		assertPeerConnectionState(t, "GetPeersByIDs", 5, list, lastSeen)

		all, err := store.GetAccountPeers(ctx, LockingStrengthNone, peerConnectionAccountID, "", "", "")
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetAccountPeers", 5, all, lastSeen)

		paginated, _, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, peerConnectionAccountID, PaginationState{}, PeerFilters{}, PeerSorting{})
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetAccountPeersPaginated", 5, paginated, lastSeen)

		account, err := sqlStore.getAccountGorm(ctx, peerConnectionAccountID)
		require.NoError(t, err)
		accountPeers := make([]*nbpeer.Peer, 0, len(account.Peers))
		for _, peer := range account.Peers {
			accountPeers = append(accountPeers, peer)
		}
		assertPeerConnectionState(t, "getAccountGorm", 5, accountPeers, lastSeen)

		if sqlStore.pgxPool() != nil {
			account, err = sqlStore.getAccountPgx(ctx, peerConnectionAccountID)
			require.NoError(t, err)
			accountPeers = accountPeers[:0]
			for _, peer := range account.Peers {
				accountPeers = append(accountPeers, peer)
			}
			assertPeerConnectionState(t, "getAccountPgx", 5, accountPeers, lastSeen)
		}
	})
}

func TestSqlStore_PeerStatusFromConnectionsLockedReads(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		lastSeen := seedPeerConnectionStates(t, store)

		for _, lock := range []LockingStrength{LockingStrengthUpdate, LockingStrengthShare} {
			for i, id := range peerConnectionStateIDs {
				byID, err := store.GetPeerByID(ctx, lock, peerConnectionAccountID, id)
				require.NoError(t, err, lock)
				byKey, err := store.GetPeerByPeerPubKey(ctx, lock, "key-"+id)
				require.NoError(t, err, lock)
				byIP, err := store.GetPeerByIP(ctx, lock, peerConnectionAccountID, net.IPv4(10, 9, 2, byte(i+1)))
				require.NoError(t, err, lock)
				assertPeerConnectionState(t, "locked GetPeerByID", 1, []*nbpeer.Peer{byID}, lastSeen)
				assertPeerConnectionState(t, "locked GetPeerByPeerPubKey", 1, []*nbpeer.Peer{byKey}, lastSeen)
				assertPeerConnectionState(t, "locked GetPeerByIP", 1, []*nbpeer.Peer{byIP}, lastSeen)
			}
		}

		_, err := store.GetPeerByID(ctx, LockingStrengthUpdate, peerConnectionAccountID, "peer-gone")
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.NotFound, sErr.Type())
	})
}

func TestSqlStore_PeerStatusFromConnectionsExpirationAndEphemeralLoaders(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		lastSeen := seedPeerConnectionStates(t, store)
		sqlStore := store.(*SqlStore)
		for _, id := range peerConnectionStateIDs {
			require.NoError(t, sqlStore.db.Model(&nbpeer.Peer{}).Where("id = ?", id).Updates(map[string]any{
				"login_expiration_enabled":      true,
				"inactivity_expiration_enabled": true,
				"ephemeral":                     true,
				"user_id":                       "user-with-peers",
			}).Error)
		}

		withExpiration, err := store.GetAccountPeersWithExpiration(ctx, LockingStrengthNone, peerConnectionAccountID)
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetAccountPeersWithExpiration", 5, withExpiration, lastSeen)

		withInactivity, err := store.GetAccountPeersWithInactivity(ctx, LockingStrengthNone, peerConnectionAccountID)
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetAccountPeersWithInactivity", 5, withInactivity, lastSeen)

		ephemeral, err := store.GetAllEphemeralPeers(ctx, LockingStrengthNone)
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetAllEphemeralPeers", 5, ephemeral, lastSeen)

		userPeers, err := store.GetUserPeers(ctx, LockingStrengthNone, peerConnectionAccountID, "user-with-peers")
		require.NoError(t, err)
		assertPeerConnectionState(t, "GetUserPeers", 5, userPeers, lastSeen)
	})
}

func TestSqlStore_PeersFilterAndSortByConnection(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		seedPeerConnectionStates(t, store)
		recent := time.Now().UTC().Add(-30 * time.Second)
		setPeerLastSeen(t, store, "peer-d", recent)

		names := func(peers []*nbpeer.Peer) []string {
			ids := make([]string, 0, len(peers))
			for _, p := range peers {
				ids = append(ids, p.ID)
			}
			return ids
		}

		connected, count, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, peerConnectionAccountID, PaginationState{}, PeerFilters{Connected: new(true)}, PeerSorting{})
		require.NoError(t, err)
		assert.Equal(t, []string{"peer-a"}, names(connected), "only a peer held by a live instance is connected")
		assert.Equal(t, 1, count)

		disconnected, count, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, peerConnectionAccountID, PaginationState{}, PeerFilters{Connected: new(false)}, PeerSorting{})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"peer-b", "peer-c", "peer-d", "peer-e"}, names(disconnected),
			"stale instance, no holder, missing instance and no record are disconnected")
		assert.Equal(t, 4, count)

		sorted := []string{"peer-a", "peer-b", "peer-c", "peer-d"}
		ascending, _, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, peerConnectionAccountID, PaginationState{}, PeerFilters{PeersIds: sorted},
			PeerSorting{Fields: []PeerSortingKey{{Field: PeerSortByLastSeen}}})
		require.NoError(t, err)
		assert.Equal(t, []string{"peer-c", "peer-b", "peer-a", "peer-d"}, names(ascending),
			"sorted by the later of the record's and its instance's last seen")

		descending, _, err := store.GetAccountPeersPaginated(ctx, LockingStrengthNone, peerConnectionAccountID, PaginationState{Page: 1, PageSize: 2}, PeerFilters{PeersIds: sorted},
			PeerSorting{Fields: []PeerSortingKey{{Field: PeerSortByLastSeen, Order: DescOrderBy}}})
		require.NoError(t, err)
		assert.Equal(t, []string{"peer-d", "peer-a"}, names(descending))
	})
}

func TestSqlStore_SavePeerLeavesConnectionAlone(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		addPeerConnectionTestPeers(t, store, "peer-a")
		require.NoError(t, store.RegisterInstance(ctx, "inst-1", "one"))
		_, err := store.ConnectPeer(ctx, peerConnectionAccountID, "peer-a", "inst-1", 5)
		require.NoError(t, err)
		stored := time.Now().UTC().Add(-3 * time.Hour)
		setPeerLastSeen(t, store, "peer-a", stored)
		before := peersRow(t, store, "peer-a")

		peer, err := store.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "peer-a")
		require.NoError(t, err)
		peer.Name = "renamed"
		peer.Status = &nbpeer.PeerStatus{Connected: false, SessionStartedAt: 0, LastSeen: time.Now().UTC(), LoginExpired: true}
		require.NoError(t, store.SavePeer(ctx, peerConnectionAccountID, peer))

		conn := getPeerConnection(t, store, "peer-a")
		assert.Equal(t, "inst-1", instanceOf(conn))
		assert.Equal(t, int64(5), conn.SessionStartedAt)
		assert.WithinDuration(t, stored, peerLastSeen(t, store, "peer-a"), time.Second)

		after := peersRow(t, store, "peer-a")
		for column, value := range before {
			if column == "name" || column == "peer_status_login_expired" || column == "peer_status_requires_approval" {
				continue
			}
			assert.Equal(t, value, after[column], "SavePeer must not change column %s", column)
		}
		reloaded, err := store.GetPeerByID(ctx, LockingStrengthNone, peerConnectionAccountID, "peer-a")
		require.NoError(t, err)
		assert.Equal(t, "renamed", reloaded.Name)
		assert.True(t, reloaded.Status.LoginExpired, "the other status columns are still saved")
		assert.True(t, reloaded.Status.Connected, "the connection state comes from the connection record")
	})
}

func TestSqlStore_LegacyPeerLastSeenBackfilled(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	require.NoError(t, err)

	conn := getPeerConnection(t, store, "ct286bi7qv930dsrrug0")
	require.NotNil(t, conn, "a peer of the legacy schema gets a connection record on startup")
	assert.Equal(t, peerConnectionAccountID, conn.AccountID)
	assert.Empty(t, instanceOf(conn))

	peer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, peerConnectionAccountID, "ct286bi7qv930dsrrug0")
	require.NoError(t, err)
	assert.False(t, peer.Status.Connected)
	assert.True(t, time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC).Equal(peer.Status.LastSeen.UTC()), "LastSeen = %v", peer.Status.LastSeen)
}
