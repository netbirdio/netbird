package manager

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/shared/management/status"
)

func newTestRepository(t *testing.T) (exitnodes.Repository, *db.Conn) {
	t.Helper()
	conn := dbtest.NewConn(t, &exitnodes.ExitNode{})
	return NewRepository(conn), conn
}

func newStoredExitNode(id, accountID, name string) *exitnodes.ExitNode {
	return &exitnodes.ExitNode{
		ID:          id,
		AccountID:   accountID,
		PublicID:    "pub-" + id,
		Name:        name,
		Description: "description of " + name,
		Enabled:     true,
		RoutingPeers: []exitnodes.RoutingPeer{
			{ID: "rp1-" + id, PublicID: "rp1-pub-" + id, Peer: "peer1", Metric: 10, Enabled: true},
			{ID: "rp2-" + id, PublicID: "rp2-pub-" + id, PeerGroups: []string{"pg1", "pg2"}, Metric: 20},
		},
		Masquerade:          true,
		Groups:              []string{"dist1"},
		AccessControlGroups: []string{"acl1"},
		AutoApply:           true,
	}
}

func assertSameExitNode(t *testing.T, want, got *exitnodes.ExitNode) {
	t.Helper()
	assert.Equal(t, want.ID, got.ID, "id")
	assert.Equal(t, want.AccountID, got.AccountID, "account id")
	assert.Equal(t, want.PublicID, got.PublicID, "public id")
	assert.Equal(t, want.Name, got.Name, "name")
	assert.Equal(t, want.Description, got.Description, "description")
	assert.Equal(t, want.Enabled, got.Enabled, "enabled")
	assert.Equal(t, want.RoutingPeers, got.RoutingPeers, "routing peers")
	assert.Equal(t, want.Masquerade, got.Masquerade, "masquerade")
	assert.Equal(t, want.Groups, got.Groups, "groups")
	assert.Equal(t, want.AccessControlGroups, got.AccessControlGroups, "access control groups")
	assert.Equal(t, want.AutoApply, got.AutoApply, "auto apply")
}

func assertNotFound(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok, "error should be a status error: %v", err)
	assert.Equal(t, status.NotFound, sErr.Type(), "error type")
}

func TestSqlRepository_CreateAndGetByID(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	node := newStoredExitNode("en1", "acc", "office")

	require.NoError(t, repo.Create(ctx, node))

	got, err := repo.GetByID(ctx, db.LockingStrengthNone, "acc", "en1")
	require.NoError(t, err)
	assertSameExitNode(t, newStoredExitNode("en1", "acc", "office"), got)
	assert.False(t, got.CreatedAt.IsZero(), "created at should be set on create")
	assert.False(t, got.UpdatedAt.IsZero(), "updated at should be set on create")
}

func TestSqlRepository_GetByID_NotFound(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en1", "acc", "office")))

	_, err := repo.GetByID(ctx, db.LockingStrengthNone, "acc", "missing")
	assertNotFound(t, err)

	_, err = repo.GetByID(ctx, db.LockingStrengthNone, "other-acc", "en1")
	assertNotFound(t, err)
}

func TestSqlRepository_ListByAccount(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, node := range []*exitnodes.ExitNode{
		newStoredExitNode("b", "acc", "second"),
		newStoredExitNode("a", "acc", "first"),
		newStoredExitNode("c", "other-acc", "foreign"),
	} {
		node.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		require.NoError(t, repo.Create(ctx, node))
	}

	nodes, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc")
	require.NoError(t, err)
	require.Len(t, nodes, 2, "only the account's exit nodes should be listed")
	assert.Equal(t, "b", nodes[0].ID, "exit nodes should be listed by creation time")
	assert.Equal(t, "a", nodes[1].ID, "exit nodes should be listed by creation time")

	nodes, err = repo.ListByAccount(ctx, db.LockingStrengthNone, "empty-acc")
	require.NoError(t, err)
	assert.Empty(t, nodes, "an account without exit nodes should list none")
}

func TestSqlRepository_Update(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en1", "acc", "office")))
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en2", "acc", "lab")))

	updated := newStoredExitNode("en1", "acc", "renamed")
	updated.Description = ""
	updated.Enabled = false
	updated.Masquerade = false
	updated.AutoApply = false
	updated.AccessControlGroups = nil
	updated.RoutingPeers = []exitnodes.RoutingPeer{{ID: "rp3", PublicID: "rp3-pub", Peer: "peer9", Metric: 5}}
	require.NoError(t, repo.Update(ctx, updated))

	got, err := repo.GetByID(ctx, db.LockingStrengthNone, "acc", "en1")
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name, "name")
	assert.Empty(t, got.Description, "description should be cleared")
	assert.False(t, got.Enabled, "enabled should be cleared")
	assert.False(t, got.Masquerade, "masquerade should be cleared")
	assert.False(t, got.AutoApply, "auto apply should be cleared")
	assert.Empty(t, got.AccessControlGroups, "access control groups should be cleared")
	assert.Equal(t, []exitnodes.RoutingPeer{{ID: "rp3", PublicID: "rp3-pub", Peer: "peer9", Metric: 5}}, got.RoutingPeers, "routing peers")

	other, err := repo.GetByID(ctx, db.LockingStrengthNone, "acc", "en2")
	require.NoError(t, err)
	assertSameExitNode(t, newStoredExitNode("en2", "acc", "lab"), other)
}

func TestSqlRepository_Update_NotFound(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en1", "acc", "office")))

	assertNotFound(t, repo.Update(ctx, newStoredExitNode("missing", "acc", "office")))

	foreign := newStoredExitNode("en1", "other-acc", "hijacked")
	assertNotFound(t, repo.Update(ctx, foreign))

	got, err := repo.GetByID(ctx, db.LockingStrengthNone, "acc", "en1")
	require.NoError(t, err)
	assert.Equal(t, "office", got.Name, "another account must not update the exit node")
}

func TestSqlRepository_Delete(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en1", "acc", "office")))
	require.NoError(t, repo.Create(ctx, newStoredExitNode("en2", "acc", "lab")))

	assertNotFound(t, repo.Delete(ctx, "other-acc", "en1"))
	require.NoError(t, repo.Delete(ctx, "acc", "en1"))
	assertNotFound(t, repo.Delete(ctx, "acc", "en1"))

	nodes, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc")
	require.NoError(t, err)
	require.Len(t, nodes, 1, "only the deleted exit node should be gone")
	assert.Equal(t, "en2", nodes[0].ID)
}

func TestSqlRepository_CreateInsideTransactionRollsBack(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()
	failure := errors.New("abort")

	err := conn.RunInTx(ctx, func(tx *db.Tx) error {
		txRepo := repo.WithTx(tx)
		require.NoError(t, txRepo.LockAccount(ctx, "acc"))
		require.NoError(t, txRepo.Create(ctx, newStoredExitNode("en1", "acc", "office")))
		nodes, err := txRepo.ListByAccount(ctx, db.LockingStrengthUpdate, "acc")
		require.NoError(t, err)
		assert.Len(t, nodes, 1, "the transaction should see its own write")
		return failure
	})
	require.ErrorIs(t, err, failure)

	nodes, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc")
	require.NoError(t, err)
	assert.Empty(t, nodes, "the write should be rolled back with the transaction")
}

func TestSqlRepository_LockAccountSerializesWritersOnPostgres(t *testing.T) {
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
		t.Skip("requires NETBIRD_STORE_ENGINE=postgres")
	}
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	conn, err := db.OpenPostgres(context.Background(), dsn, db.DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.AutoMigrate(&exitnodes.ExitNode{}))
	require.NoError(t, conn.DB(nil).Exec("DELETE FROM exit_nodes").Error)

	repo := NewRepository(conn)
	ctx := context.Background()

	// The first writer takes the account lock and holds it until released.
	locked := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- conn.RunInTx(ctx, func(tx *db.Tx) error {
			txRepo := repo.WithTx(tx)
			if err := txRepo.LockAccount(ctx, "acc"); err != nil {
				close(locked)
				return err
			}
			close(locked)
			<-release
			return txRepo.Create(ctx, newStoredExitNode("en1", "acc", "office"))
		})
	}()
	<-locked

	// The second writer must block on the lock, then see the first one's row,
	// which a row lock alone would not give it.
	type result struct {
		nodes []*exitnodes.ExitNode
		err   error
	}
	second := make(chan result, 1)
	go func() {
		var nodes []*exitnodes.ExitNode
		err := conn.RunInTx(ctx, func(tx *db.Tx) error {
			txRepo := repo.WithTx(tx)
			if err := txRepo.LockAccount(ctx, "acc"); err != nil {
				return err
			}
			var err error
			nodes, err = txRepo.ListByAccount(ctx, db.LockingStrengthUpdate, "acc")
			return err
		})
		second <- result{nodes: nodes, err: err}
	}()

	select {
	case <-second:
		t.Fatal("the second writer should wait for the first one's account lock")
	case <-time.After(300 * time.Millisecond):
	}

	// Another account is not serialized behind the lock.
	otherDone := make(chan error, 1)
	go func() {
		otherDone <- conn.RunInTx(ctx, func(tx *db.Tx) error {
			return repo.WithTx(tx).LockAccount(ctx, "other-acc")
		})
	}()
	select {
	case err := <-otherDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a different account should not wait for the lock")
	}

	close(release)
	require.NoError(t, <-firstDone)
	res := <-second
	require.NoError(t, res.err)
	require.Len(t, res.nodes, 1, "the second writer should see the row committed by the first")
	assert.Equal(t, "en1", res.nodes[0].ID)
}
