package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
	"github.com/netbirdio/netbird/shared/management/status"
)

// newTestConn returns a connection with the exit node tables and a minimal accounts table
// holding accountIDs, whose rows LockAccount locks. In production the exit node tables
// live in the store's database next to the real accounts table.
func newTestConn(t *testing.T, accountIDs ...string) *db.Conn {
	t.Helper()
	conn := dbtest.NewConn(t, &exitnodes.ExitNode{}, &exitnodes.Peer{})
	gormDB := conn.DB(nil)
	require.NoError(t, gormDB.Exec("CREATE TABLE accounts (id VARCHAR(255) PRIMARY KEY, network_serial BIGINT NOT NULL DEFAULT 0)").Error)
	for _, id := range accountIDs {
		require.NoError(t, gormDB.Exec("INSERT INTO accounts (id) VALUES (?)", id).Error)
	}
	return conn
}

func newTestRepository(t *testing.T) (exitnodes.Repository, *db.Conn) {
	t.Helper()
	conn := newTestConn(t, "acc-a", "acc-b")
	return NewRepository(conn), conn
}

func newStoredExitNode(id exitnodes.ID, accountID, name string, peers ...exitnodes.Peer) *exitnodes.ExitNode {
	node := &exitnodes.ExitNode{
		ID:          id,
		AccountID:   accountID,
		Name:        name,
		Description: name + " description",
		Enabled:     true,
		AutoApply:   true,
		Peers:       peers,
	}
	node.BindPeers()
	return node
}

func createInTx(t *testing.T, conn *db.Conn, repo exitnodes.Repository, node *exitnodes.ExitNode) error {
	t.Helper()
	return conn.RunInTx(context.Background(), func(tx *db.Tx) error {
		return repo.WithTx(tx).Create(context.Background(), node)
	})
}

func peerIDs(node *exitnodes.ExitNode) []string {
	ids := make([]string, 0, len(node.Peers))
	for _, p := range node.Peers {
		ids = append(ids, p.PeerID)
	}
	return ids
}

func TestSqlRepository_CreateAndGet(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	node := newStoredExitNode("en-1", "acc-a", "EU Egress",
		exitnodes.Peer{PeerID: "peer-2", PublicID: "peer-2-public", Metric: 200, Enabled: false},
		exitnodes.Peer{PeerID: "peer-1", PublicID: "peer-1-public", Metric: 100, Enabled: true},
	)
	node.PublicID = "en-1-public"
	require.NoError(t, createInTx(t, conn, repo, node))

	got, err := repo.Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
	require.NoError(t, err)
	assert.Equal(t, "EU Egress", got.Name)
	assert.Equal(t, "en-1-public", got.PublicID)
	assert.Equal(t, "EU Egress description", got.Description)
	assert.True(t, got.Enabled)
	assert.True(t, got.AutoApply)
	assert.Equal(t, []exitnodes.Peer{
		{ExitNodeID: "en-1", AccountID: "acc-a", PeerID: "peer-1", PublicID: "peer-1-public", Metric: 100, Enabled: true},
		{ExitNodeID: "en-1", AccountID: "acc-a", PeerID: "peer-2", PublicID: "peer-2-public", Metric: 200, Enabled: false},
	}, got.Peers, "peers should come back ordered by metric with every field stored")

	_, err = repo.Get(ctx, db.LockingStrengthNone, "acc-b", "en-1")
	assertStatus(t, err, status.NotFound)
}

func TestSqlRepository_LockAccount(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	err := conn.RunInTx(ctx, func(tx *db.Tx) error {
		return repo.WithTx(tx).LockAccount(ctx, "acc-a")
	})
	assert.NoError(t, err, "an existing account should be locked")

	err = conn.RunInTx(ctx, func(tx *db.Tx) error {
		return repo.WithTx(tx).LockAccount(ctx, "acc-missing")
	})
	assertStatus(t, err, status.NotFound)
}

func TestSqlRepository_IncrementNetworkSerial(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	serial := func(accountID string) int64 {
		var value int64
		require.NoError(t, conn.DB(nil).Table("accounts").Where("id = ?", accountID).Pluck("network_serial", &value).Error)
		return value
	}

	require.NoError(t, repo.IncrementNetworkSerial(ctx, "acc-a"))
	require.NoError(t, repo.IncrementNetworkSerial(ctx, "acc-a"))
	assert.Equal(t, int64(2), serial("acc-a"), "each call should bump the serial by one")
	assert.Equal(t, int64(0), serial("acc-b"), "other accounts should keep their serial")

	assertStatus(t, repo.IncrementNetworkSerial(ctx, "acc-missing"), status.NotFound)
}

func TestSqlRepository_ListByAccount(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-2", "acc-a", "US Egress", exitnodes.Peer{PeerID: "peer-2", Metric: 100})))
	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-1", "acc-a", "EU Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})))
	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-3", "acc-b", "Other", exitnodes.Peer{PeerID: "peer-3", Metric: 100})))

	nodes, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc-a")
	require.NoError(t, err)
	require.Len(t, nodes, 2, "only the account's exit nodes should be listed")
	assert.Equal(t, exitnodes.ID("en-1"), nodes[0].ID, "exit nodes should be ordered by name")
	assert.Equal(t, []string{"peer-1"}, peerIDs(nodes[0]))
	assert.Equal(t, exitnodes.ID("en-2"), nodes[1].ID)
	assert.Equal(t, []string{"peer-2"}, peerIDs(nodes[1]))

	nodes, err = repo.ListByAccount(ctx, db.LockingStrengthNone, "acc-none")
	require.NoError(t, err)
	assert.Empty(t, nodes)
}

func TestSqlRepository_UpdateReplacesPeers(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	original := newStoredExitNode("en-1", "acc-a", "EU Egress",
		exitnodes.Peer{PeerID: "peer-1", Metric: 100, Enabled: true},
		exitnodes.Peer{PeerID: "peer-2", Metric: 200, Enabled: true},
	)
	original.PublicID = "en-1-public"
	require.NoError(t, createInTx(t, conn, repo, original))

	update := newStoredExitNode("en-1", "acc-a", "EU Egress HA",
		exitnodes.Peer{PeerID: "peer-2", PublicID: "peer-2-public", Metric: 50, Enabled: false},
		exitnodes.Peer{PeerID: "peer-3", PublicID: "peer-3-public", Metric: 300, Enabled: true},
	)
	update.PublicID = "changed"
	update.Description = ""
	update.Enabled = false
	update.AutoApply = false
	require.NoError(t, conn.RunInTx(ctx, func(tx *db.Tx) error {
		return repo.WithTx(tx).Update(ctx, update)
	}))

	got, err := repo.Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
	require.NoError(t, err)
	assert.Equal(t, "EU Egress HA", got.Name)
	assert.Equal(t, "en-1-public", got.PublicID, "update should never change the public ID")
	assert.Equal(t, "", got.Description, "an empty description should be stored")
	assert.False(t, got.Enabled, "false should be stored, not skipped as a zero value")
	assert.False(t, got.AutoApply, "false should be stored, not skipped as a zero value")
	assert.Equal(t, []exitnodes.Peer{
		{ExitNodeID: "en-1", AccountID: "acc-a", PeerID: "peer-2", PublicID: "peer-2-public", Metric: 50, Enabled: false},
		{ExitNodeID: "en-1", AccountID: "acc-a", PeerID: "peer-3", PublicID: "peer-3-public", Metric: 300, Enabled: true},
	}, got.Peers, "update should replace the peer list")
}

func TestSqlRepository_Delete(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-1", "acc-a", "EU Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})))

	deleteInTx := func(accountID string) error {
		return conn.RunInTx(ctx, func(tx *db.Tx) error {
			return repo.WithTx(tx).Delete(ctx, accountID, "en-1")
		})
	}

	assertStatus(t, deleteInTx("acc-b"), status.NotFound)
	require.NoError(t, deleteInTx("acc-a"))

	_, err := repo.Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
	assertStatus(t, err, status.NotFound)

	var peerRows int64
	require.NoError(t, conn.DB(nil).Model(&exitnodes.Peer{}).Count(&peerRows).Error)
	assert.Zero(t, peerRows, "deleting an exit node should delete its peers")

	// The peer is free again for another exit node.
	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-2", "acc-a", "US Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})))
}

func TestSqlRepository_PeerInOneExitNodePerAccount(t *testing.T) {
	repo, conn := newTestRepository(t)

	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-1", "acc-a", "EU Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})))

	err := createInTx(t, conn, repo, newStoredExitNode("en-2", "acc-a", "US Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100}))
	assert.Error(t, err, "the unique index should reject a peer in a second exit node of the account")

	_, err = repo.Get(context.Background(), db.LockingStrengthNone, "acc-a", "en-2")
	assertStatus(t, err, status.NotFound)
}

func TestSqlRepository_WithTxRollsBack(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()

	errAbort := errors.New("abort")
	err := conn.RunInTx(ctx, func(tx *db.Tx) error {
		node := newStoredExitNode("en-1", "acc-a", "EU Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})
		if err := repo.WithTx(tx).Create(ctx, node); err != nil {
			return err
		}
		return errAbort
	})
	require.ErrorIs(t, err, errAbort)

	_, err = repo.Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
	assertStatus(t, err, status.NotFound)

	var peerRows int64
	require.NoError(t, conn.DB(nil).Model(&exitnodes.Peer{}).Count(&peerRows).Error)
	assert.Zero(t, peerRows, "peers written in a rolled back transaction should be gone")
}

func TestSqlRepository_ReadsFollowRequestContext(t *testing.T) {
	repo, conn := newTestRepository(t)
	require.NoError(t, createInTx(t, conn, repo, newStoredExitNode("en-1", "acc-a", "EU Egress", exitnodes.Peer{PeerID: "peer-1", Metric: 100})))

	// A cancelled request must not run its queries outside a transaction.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc-a")
	assertStatus(t, err, status.Internal)
	_, err = repo.Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
	assertStatus(t, err, status.Internal)

	// Inside a transaction the queries keep the transaction's context, so a request
	// context passed to a single call does not cut it short.
	err = conn.RunInTx(context.Background(), func(tx *db.Tx) error {
		_, err := repo.WithTx(tx).Get(ctx, db.LockingStrengthNone, "acc-a", "en-1")
		return err
	})
	assert.NoError(t, err, "a read inside a transaction should run on the transaction's context")
}
