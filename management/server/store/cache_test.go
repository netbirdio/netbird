package store

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlStore_CacheHit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	require.NoError(t, err)

	ctx := context.Background()
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "ct286bi7qv930dsrrug0"

	sqlStore := store.(*SqlStore)

	// First call - should hit the database
	peer1, err := sqlStore.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	require.NoError(t, err)
	require.NotNil(t, peer1)

	// Get the underlying database connection
	db, err := sqlStore.db.DB()
	require.NoError(t, err)

	// Get DB stats before second call
	statsBefore := db.Stats()

	// Second call - should hit the cache, not the database
	peer2, err := sqlStore.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	require.NoError(t, err)
	require.NotNil(t, peer2)

	// Get DB stats after second call
	statsAfter := db.Stats()

	// Verify no additional database connections were opened for the cached query
	// The OpenConnections count should be the same or very similar
	assert.Equal(t, statsBefore.InUse, statsAfter.InUse, "Cache hit should not open new database connections")

	// Verify both peers are equal
	assert.Equal(t, peer1.ID, peer2.ID)
	assert.Equal(t, peer1.Name, peer2.Name)
}

func TestSqlStore_CacheInvalidationAcrossInstances(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container for shared cache
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// Set the Redis URL environment variable for both stores
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	// Create a shared SQLite database in a temp directory with cache=shared mode
	// This allows multiple connections to the same database
	tempDir := t.TempDir()

	// Create first store instance with shared database
	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "../testdata/store.sql", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	// Create second store instance connecting to the SAME database file
	// Both stores will share the same underlying database AND the same Redis cache
	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "ct286bi7qv930dsrrug0"

	// Store 1: Fetch peer (populates cache)
	peer1, err := store1.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	require.NoError(t, err)
	require.NotNil(t, peer1)

	// Store 2: Fetch same peer (should use cache)
	peer2, err := store2.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	require.NoError(t, err)
	require.NotNil(t, peer2)
	assert.Equal(t, peer1.ID, peer2.ID)

	// Store 1: Modify the peer
	peer1.Name = "updated-peer-name"
	err = store1.SavePeer(ctx, accountID, peer1)
	require.NoError(t, err)

	// Store 2: Fetch the peer again - should get updated data (cache was invalidated)
	peer2Updated, err := store2.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	require.NoError(t, err)
	require.NotNil(t, peer2Updated)

	// Verify the name was updated via cache invalidation
	assert.Equal(t, "updated-peer-name", peer2Updated.Name,
		"Cache should have been invalidated, store 2 should see the update from store 1")
}

func TestSqlStore_CacheGetAccountWithAssociations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container for shared cache
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// Set the Redis URL environment variable for both stores
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	// Create a shared SQLite database in a temp directory with cache=shared mode
	// This allows multiple connections to the same database
	tempDir := t.TempDir()

	// Create first store instance with shared database
	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	// Create second store instance connecting to the SAME database file
	// Both stores will share the same underlying database AND the same Redis cache
	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create a fresh account
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Store 1: Fetch account (populates cache)
	account1, err := store1.GetAccount(ctx, accountID)
	require.NoError(t, err)
	require.NotNil(t, account1)

	// Store 2: Fetch same account (should use cache)
	account2, err := store2.GetAccount(ctx, accountID)
	require.NoError(t, err)
	require.NotNil(t, account2)
	assert.Equal(t, account1.Id, account2.Id)

	// Store 1: Modify the account
	account1.Domain = "updated-domain.example.com"
	err = store1.SaveAccount(ctx, account1)
	require.NoError(t, err)

	// Store 2: Fetch the account again - should get updated data (cache was invalidated)
	account2Updated, err := store2.GetAccount(ctx, accountID)
	require.NoError(t, err)
	require.NotNil(t, account2Updated)

	// Verify the domain was updated via cache invalidation
	assert.Equal(t, "updated-domain.example.com", account2Updated.Domain,
		"Cache should have been invalidated, store 2 should see the update from store 1")
}

func TestSqlStore_CacheGetGroupWithAssociations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container for shared cache
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// Set the Redis URL environment variable for both stores
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	// Create a shared SQLite database in a temp directory with cache=shared mode
	// This allows multiple connections to the same database
	tempDir := t.TempDir()

	// Create first store instance with shared database
	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	// Create second store instance connecting to the SAME database file
	// Both stores will share the same underlying database AND the same Redis cache
	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create a fresh account
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	// Add peers to the account
	peer1 := &nbpeer.Peer{
		Key:       "peer-key-1",
		ID:        "peer-id-1",
		IP:        net.IP{100, 64, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
		Name:      "Test Peer 1",
		DNSLabel:  "test-peer-1",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer1.ID] = peer1

	peer2 := &nbpeer.Peer{
		Key:       "peer-key-2",
		ID:        "peer-id-2",
		IP:        net.IP{100, 64, 0, 2},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
		Name:      "Test Peer 2",
		DNSLabel:  "test-peer-2",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer2.ID] = peer2

	// Create a group with peers (SaveAccount will convert to GroupPeers)
	group := &types.Group{
		ID:        "group-id-1",
		AccountID: accountID,
		Name:      "Test Group",
		Issued:    "api",
		Peers:     []string{peer1.ID, peer2.ID},
		Resources: []types.Resource{},
	}
	account.Groups = map[string]*types.Group{
		group.ID: group,
	}

	// Save the account with all data using store1
	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Store 1: Fetch group (populates cache)
	group1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.NotNil(t, group1)
	require.NotEmpty(t, group1.Peers, "First call should load Peers (converted from GroupPeers)")
	require.Len(t, group1.Peers, 2, "First call should load both Peers")

	// Store 2: Fetch same group (should use cache)
	group2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.NotNil(t, group2)
	require.NotEmpty(t, group2.Peers, "Cached group should have Peers")
	require.Len(t, group2.Peers, 2, "Cached group should have both Peers")

	// Verify data matches between both stores
	assert.Equal(t, len(group1.Peers), len(group2.Peers))
	assert.Equal(t, group1.Name, group2.Name)
	assert.ElementsMatch(t, group1.Peers, group2.Peers)

	// Modify the group with store1 (update name and remove one peer using UpdateGroup and RemovePeerFromGroup)
	group1.Name = "Modified Group Name"
	err = store1.UpdateGroup(ctx, group1)
	require.NoError(t, err)

	// Remove peer2 from the group
	err = store1.RemovePeerFromGroup(ctx, peer2.ID, group.ID)
	require.NoError(t, err)

	// Store2: Fetch the modified group (should get updated data, not stale cache)
	group3, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.NotNil(t, group3)

	// Verify the updated data is visible from store2
	assert.Equal(t, "Modified Group Name", group3.Name, "Store2 should see the updated group name")
	assert.Len(t, group3.Peers, 1, "Store2 should see only one peer after modification")
	assert.Contains(t, group3.Peers, peer1.ID, "Store2 should see peer1")
	assert.NotContains(t, group3.Peers, peer2.ID, "Store2 should NOT see peer2 after removal")
}

// TestSqlStore_ConcurrentTransactionWithCache tests concurrent read/write operations across
// multiple store instances with caching enabled, ensuring proper transaction isolation
// and cache invalidation.
func TestSqlStore_ConcurrentTransactionWithCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	// if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
	// 	t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	// }

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container for shared cache
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	tempDir := t.TempDir()

	// Create two store instances sharing the same database and Redis cache
	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create initial account with a group
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	peer1 := &nbpeer.Peer{
		Key:       "peer-key-1",
		ID:        "peer-id-1",
		IP:        net.IP{100, 64, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
		Name:      "Test Peer 1",
		DNSLabel:  "test-peer-1",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer1.ID] = peer1

	group := &types.Group{
		ID:        "group-id-1",
		AccountID: accountID,
		Name:      "Initial Group",
		Issued:    "api",
		Peers:     []string{peer1.ID},
		Resources: []types.Resource{},
	}
	account.Groups = map[string]*types.Group{group.ID: group}

	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Synchronization primitives
	var wg sync.WaitGroup
	txStarted := make(chan struct{})
	txMidPoint := make(chan struct{})
	readDone := make(chan struct{})

	// Test scenario: Store1 starts a transaction, holds a write lock, modifies data
	// while Store2 attempts concurrent reads at different points

	var store1GroupAfterUpdate *types.Group
	var store2GroupBeforeTx *types.Group
	var txErr, read1Err, read2Err, read3Err error

	wg.Add(2)

	// Goroutine 1: Store1 executes a long transaction with write lock
	go func() {
		defer wg.Done()

		txErr = store1.ExecuteInTransaction(ctx, func(transaction Store) error {
			// Acquire write lock on the group
			g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
			if err != nil {
				return err
			}

			// Signal that transaction has started and lock is held
			close(txStarted)

			// Wait briefly to simulate processing time
			time.Sleep(100 * time.Millisecond)

			// Modify the group
			g.Name = "Modified During Transaction"
			err = transaction.UpdateGroup(ctx, g)
			if err != nil {
				return err
			}

			// Signal mid-point of transaction
			close(txMidPoint)

			// Wait for the concurrent read to attempt
			time.Sleep(100 * time.Millisecond)

			// Read again within same transaction to verify consistency
			g2, err := transaction.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
			if err != nil {
				return err
			}
			store1GroupAfterUpdate = g2

			// Wait for read goroutine to finish before committing
			<-readDone

			return nil
		})
	}()

	// Goroutine 2: Store2 attempts reads at different points
	go func() {
		defer wg.Done()
		defer close(readDone)

		// Read before transaction starts (should get cached original data)
		store2GroupBeforeTx, read1Err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)

		// Wait for transaction to start and acquire lock
		<-txStarted

		// Attempt to read during transaction (with write lock held by store1)
		// This should either block and wait, or read stale cached data depending on implementation
		_, read2Err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)

		// Wait for mid-point
		<-txMidPoint

		// Another read during transaction
		_, read3Err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	}()

	wg.Wait()

	// Verify no errors occurred
	require.NoError(t, txErr, "Transaction should complete without errors")
	require.NoError(t, read1Err, "Read before transaction should succeed")
	require.NoError(t, read2Err, "Read during transaction should succeed")
	require.NoError(t, read3Err, "Read after transaction midpoint should succeed")

	// Verify transaction isolation: reads within the transaction see the updated data
	require.Equal(t, "Modified During Transaction", store1GroupAfterUpdate.Name,
		"Within transaction, should see modified data")

	// Verify that store2 read before transaction shows original data
	require.Equal(t, "Initial Group", store2GroupBeforeTx.Name,
		"Before transaction, should see original data")

	// After transaction commits, verify cache was invalidated and store2 sees new data
	finalGroup2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.Equal(t, "Modified During Transaction", finalGroup2.Name,
		"After transaction commit, store2 should see updated data through cache invalidation")

	// After transaction commits, verify cache was invalidated and store2 sees new data
	finalGroup1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.Equal(t, "Modified During Transaction", finalGroup1.Name,
		"After transaction commit, store2 should see updated data through cache invalidation")
}

// TestSqlStore_MultipleTransactionsCacheInvalidation tests cache invalidation with
// multiple concurrent transactions modifying different entities.
func TestSqlStore_MultipleTransactionsCacheInvalidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	// if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
	// 	t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	// }

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	tempDir := t.TempDir()

	// Create three store instances
	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	store3, cleanUp3, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp3)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create account with multiple groups
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	peer1 := &nbpeer.Peer{
		Key:       "peer-key-1",
		ID:        "peer-id-1",
		IP:        net.IP{100, 64, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
		Name:      "Test Peer 1",
		DNSLabel:  "test-peer-1",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer1.ID] = peer1

	group1 := &types.Group{
		ID:        "group-id-1",
		AccountID: accountID,
		Name:      "Group 1",
		Issued:    "api",
		Peers:     []string{peer1.ID},
		Resources: []types.Resource{},
	}

	group2 := &types.Group{
		ID:        "group-id-2",
		AccountID: accountID,
		Name:      "Group 2",
		Issued:    "api",
		Peers:     []string{peer1.ID},
		Resources: []types.Resource{},
	}

	account.Groups = map[string]*types.Group{
		group1.ID: group1,
		group2.ID: group2,
	}

	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Pre-populate caches by reading from all stores
	_, err = store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group1.ID)
	require.NoError(t, err)
	_, err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group1.ID)
	require.NoError(t, err)
	_, err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group2.ID)
	require.NoError(t, err)
	_, err = store3.GetGroupByID(ctx, LockingStrengthShare, accountID, group2.ID)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var tx1Err, tx2Err error
	startSignal := make(chan struct{})

	wg.Add(2)

	// Transaction 1: Modify group1 via store1
	go func() {
		defer wg.Done()
		<-startSignal

		tx1Err = store1.ExecuteInTransaction(ctx, func(transaction Store) error {
			g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group1.ID)
			if err != nil {
				return err
			}

			g.Name = "Group 1 Modified"
			return transaction.UpdateGroup(ctx, g)
		})
	}()

	// Transaction 2: Modify group2 via store2
	go func() {
		defer wg.Done()
		<-startSignal

		tx2Err = store2.ExecuteInTransaction(ctx, func(transaction Store) error {
			g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group2.ID)
			if err != nil {
				return err
			}

			g.Name = "Group 2 Modified"
			return transaction.UpdateGroup(ctx, g)
		})
	}()

	// Start both transactions concurrently
	close(startSignal)
	wg.Wait()

	// Both transactions should succeed
	require.NoError(t, tx1Err)
	require.NoError(t, tx2Err)

	// Verify all stores see the updated data (cache invalidation worked)
	// Store3 should see updates from both transactions
	g1FromStore3, err := store3.GetGroupByID(ctx, LockingStrengthShare, accountID, group1.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 1 Modified", g1FromStore3.Name,
		"Store3 should see group1 update from store1's transaction")

	g2FromStore3, err := store3.GetGroupByID(ctx, LockingStrengthShare, accountID, group2.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 2 Modified", g2FromStore3.Name,
		"Store3 should see group2 update from store2's transaction")

	// Store1 should see its own update and also group2's update
	g1FromStore1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group1.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 1 Modified", g1FromStore1.Name)

	g2FromStore1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group2.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 2 Modified", g2FromStore1.Name,
		"Store1 should see group2 update from store2's transaction")

	// Store2 should see its own update and also group1's update
	g2FromStore2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group2.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 2 Modified", g2FromStore2.Name)

	g1FromStore2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group1.ID)
	require.NoError(t, err)
	assert.Equal(t, "Group 1 Modified", g1FromStore2.Name,
		"Store2 should see group1 update from store1's transaction")
}

// TestSqlStore_ReadAfterWriteConsistency tests read-after-write consistency
// both within the same transaction and across different store instances.
func TestSqlStore_ReadAfterWriteConsistency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	tempDir := t.TempDir()

	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create account
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	peer1 := &nbpeer.Peer{
		Key:       "peer-key-1",
		ID:        "peer-id-1",
		IP:        net.IP{100, 64, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
		Name:      "Test Peer 1",
		DNSLabel:  "test-peer-1",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer1.ID] = peer1

	group := &types.Group{
		ID:        "group-id-1",
		AccountID: accountID,
		Name:      "Version 0",
		Issued:    "api",
		Peers:     []string{peer1.ID},
		Resources: []types.Resource{},
	}
	account.Groups = map[string]*types.Group{group.ID: group}

	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Test 1: Read-after-write within the same transaction
	t.Run("ReadAfterWriteWithinTransaction", func(t *testing.T) {
		err := store1.ExecuteInTransaction(ctx, func(transaction Store) error {
			// Read initial state
			g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
			if err != nil {
				return err
			}
			assert.Equal(t, "Version 0", g.Name)

			// Write update
			g.Name = "Version 1"
			err = transaction.UpdateGroup(ctx, g)
			if err != nil {
				return err
			}

			// Read immediately after write within same transaction
			g2, err := transaction.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
			if err != nil {
				return err
			}
			assert.Equal(t, "Version 1", g2.Name,
				"Should see updated data within same transaction")

			// Multiple updates and reads
			g2.Name = "Version 2"
			err = transaction.UpdateGroup(ctx, g2)
			if err != nil {
				return err
			}

			g3, err := transaction.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
			if err != nil {
				return err
			}
			assert.Equal(t, "Version 2", g3.Name,
				"Should see latest update within same transaction")

			return nil
		})
		require.NoError(t, err)
	})

	// Test 2: Read-after-write across different store instances
	t.Run("ReadAfterWriteAcrossStores", func(t *testing.T) {
		// Store1 writes
		err := store1.ExecuteInTransaction(ctx, func(transaction Store) error {
			g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
			if err != nil {
				return err
			}
			g.Name = "Version 3"
			return transaction.UpdateGroup(ctx, g)
		})
		require.NoError(t, err)

		// Store2 reads immediately after
		g, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
		require.NoError(t, err)
		assert.Equal(t, "Version 3", g.Name,
			"Store2 should see write from Store1 after transaction commits")

		// Store1 reads its own write
		g1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
		require.NoError(t, err)
		assert.Equal(t, "Version 3", g1.Name,
			"Store1 should see its own write")
	})

	// Test 3: Rapid sequential updates with interleaved reads
	t.Run("RapidSequentialUpdates", func(t *testing.T) {
		for i := 4; i <= 10; i++ {
			expectedName := fmt.Sprintf("Version %d", i)

			// Store1 writes
			err := store1.ExecuteInTransaction(ctx, func(transaction Store) error {
				g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
				if err != nil {
					return err
				}
				g.Name = expectedName
				return transaction.UpdateGroup(ctx, g)
			})
			require.NoError(t, err)

			// Both stores should see the update
			g1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
			require.NoError(t, err)
			assert.Equal(t, expectedName, g1.Name,
				"Store1 should see version %d", i)

			g2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
			require.NoError(t, err)
			assert.Equal(t, expectedName, g2.Name,
				"Store2 should see version %d after cache invalidation", i)
		}
	})
}

// TestSqlStore_TransactionRollbackCacheConsistency tests that cache remains consistent
// when transactions are rolled back due to errors.
func TestSqlStore_TransactionRollbackCacheConsistency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	if os.Getenv("NETBIRD_STORE_ENGINE") != "sqlite" {
		t.Skip("Skipping test because NewTestStoreFromSQL doesn't share db")
	}

	t.Setenv(storeCacheEnabledEnv, "true")

	ctx := context.Background()

	// Start Redis container
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	require.NoError(t, err)
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	t.Setenv(storeCacheRedisAddrEnv, redisURL)

	tempDir := t.TempDir()

	store1, cleanUp1, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp1)
	require.NoError(t, err)

	store2, cleanUp2, err := NewTestStoreFromSQL(ctx, "", tempDir)
	t.Cleanup(cleanUp2)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	// Create account
	account := newAccountWithId(ctx, accountID, userID, "test.com")

	peer1 := &nbpeer.Peer{
		Key:       "peer-key-1",
		ID:        "peer-id-1",
		IP:        net.IP{100, 64, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
		Name:      "Test Peer 1",
		DNSLabel:  "test-peer-1",
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		UserID:    userID,
	}
	account.Peers[peer1.ID] = peer1

	group := &types.Group{
		ID:        "group-id-1",
		AccountID: accountID,
		Name:      "Original Name",
		Issued:    "api",
		Peers:     []string{peer1.ID},
		Resources: []types.Resource{},
	}
	account.Groups = map[string]*types.Group{group.ID: group}

	err = store1.SaveAccount(ctx, account)
	require.NoError(t, err)

	// Populate cache
	originalGroup, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	require.Equal(t, "Original Name", originalGroup.Name)

	// Attempt a transaction that will fail and rollback
	expectedErr := fmt.Errorf("intentional error for rollback test")
	err = store1.ExecuteInTransaction(ctx, func(transaction Store) error {
		g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
		if err != nil {
			return err
		}

		// Modify the group
		g.Name = "This Should Not Persist"
		err = transaction.UpdateGroup(ctx, g)
		if err != nil {
			return err
		}

		// Intentionally return error to trigger rollback
		return expectedErr
	})
	require.Error(t, err)
	require.ErrorIs(t, err, expectedErr)

	// Verify that both stores still see the original data (transaction was rolled back)
	g1, err := store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "Original Name", g1.Name,
		"Store1 should still see original name after rollback")

	g2, err := store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "Original Name", g2.Name,
		"Store2 should still see original name after rollback")

	// Now perform a successful transaction
	err = store1.ExecuteInTransaction(ctx, func(transaction Store) error {
		g, err := transaction.GetGroupByID(ctx, LockingStrengthUpdate, accountID, group.ID)
		if err != nil {
			return err
		}
		g.Name = "Successfully Updated"
		return transaction.UpdateGroup(ctx, g)
	})
	require.NoError(t, err)

	// Verify both stores see the successful update
	g1, err = store1.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "Successfully Updated", g1.Name)

	g2, err = store2.GetGroupByID(ctx, LockingStrengthShare, accountID, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "Successfully Updated", g2.Name)
}
