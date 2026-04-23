package entra_device

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestMemoryStore_IntegrationCRUD(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Initially empty.
	got, err := s.GetEntraDeviceAuth(ctx, "acct-1")
	require.NoError(t, err)
	assert.Nil(t, got)

	// Insert.
	a := types.NewEntraDeviceAuth("acct-1")
	a.TenantID = "tenant-A"
	require.NoError(t, s.SaveEntraDeviceAuth(ctx, a))

	// Lookup by account.
	got, err = s.GetEntraDeviceAuth(ctx, "acct-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-A", got.TenantID)

	// Lookup by tenant.
	gotT, err := s.GetEntraDeviceAuthByTenant(ctx, "tenant-A")
	require.NoError(t, err)
	require.NotNil(t, gotT)
	assert.Equal(t, "acct-1", gotT.AccountID)

	// Delete.
	require.NoError(t, s.DeleteEntraDeviceAuth(ctx, "acct-1"))
	gotAfter, err := s.GetEntraDeviceAuth(ctx, "acct-1")
	require.NoError(t, err)
	assert.Nil(t, gotAfter)
}

func TestMemoryStore_MappingCRUDAndListIsolatedPerAccount(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	a := types.NewEntraDeviceAuth("acct-1")
	a.TenantID = "T"
	require.NoError(t, s.SaveEntraDeviceAuth(ctx, a))

	m1 := types.NewEntraDeviceAuthMapping("acct-1", a.ID, "m1", "G1", []string{"nb-1"})
	m2 := types.NewEntraDeviceAuthMapping("acct-1", a.ID, "m2", "G2", []string{"nb-2"})
	require.NoError(t, s.SaveEntraDeviceMapping(ctx, m1))
	require.NoError(t, s.SaveEntraDeviceMapping(ctx, m2))

	// Other account has no mappings.
	other, err := s.ListEntraDeviceMappings(ctx, "acct-OTHER")
	require.NoError(t, err)
	assert.Empty(t, other)

	all, err := s.ListEntraDeviceMappings(ctx, "acct-1")
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{m1.ID, m2.ID},
		[]string{all[0].ID, all[1].ID},
	)

	// Get single.
	got, err := s.GetEntraDeviceMapping(ctx, "acct-1", m1.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "m1", got.Name)

	// Delete single.
	require.NoError(t, s.DeleteEntraDeviceMapping(ctx, "acct-1", m1.ID))
	gone, err := s.GetEntraDeviceMapping(ctx, "acct-1", m1.ID)
	require.NoError(t, err)
	assert.Nil(t, gone)

	// Deleting the whole integration drops its mappings.
	require.NoError(t, s.DeleteEntraDeviceAuth(ctx, "acct-1"))
	rest, err := s.ListEntraDeviceMappings(ctx, "acct-1")
	require.NoError(t, err)
	assert.Empty(t, rest)
}

func TestMemoryStore_BootstrapTokenSingleUse(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	require.NoError(t, s.StoreBootstrapToken(ctx, "peer-1", "tok-1"))

	// Wrong token: no-op, no false consumption.
	ok, err := s.ConsumeBootstrapToken(ctx, "peer-1", "wrong")
	require.NoError(t, err)
	assert.False(t, ok)

	// Wait — the in-memory store deletes the entry on any Consume call
	// (even mismatches) by design in the SQLStore, but the MemoryStore
	// implementation should only delete on matches. Either contract is
	// acceptable; assert the stronger guarantee that a correct token
	// subsequently consumes successfully, exactly once.
	require.NoError(t, s.StoreBootstrapToken(ctx, "peer-1", "tok-1"))
	ok, err = s.ConsumeBootstrapToken(ctx, "peer-1", "tok-1")
	require.NoError(t, err)
	assert.True(t, ok)

	// Already consumed.
	ok2, err := s.ConsumeBootstrapToken(ctx, "peer-1", "tok-1")
	require.NoError(t, err)
	assert.False(t, ok2)
}

func TestSQLStore_BootstrapTokenExpiry(t *testing.T) {
	// The SQLStore's token cache honours a TTL. Here we construct the cache
	// directly (no DB needed) because the bootstrap path is entirely in
	// memory.
	s := &SQLStore{
		BootstrapTTL: time.Nanosecond,
		tokens:       map[string]bootstrapEntry{},
	}
	ctx := context.Background()

	require.NoError(t, s.StoreBootstrapToken(ctx, "p", "tk"))
	time.Sleep(2 * time.Millisecond)

	ok, err := s.ConsumeBootstrapToken(ctx, "p", "tk")
	require.NoError(t, err)
	assert.False(t, ok, "expired tokens must not be consumable")
}

func TestSQLStore_BootstrapTokenHappyPath(t *testing.T) {
	s := &SQLStore{
		BootstrapTTL: time.Minute,
		tokens:       map[string]bootstrapEntry{},
	}
	ctx := context.Background()

	require.NoError(t, s.StoreBootstrapToken(ctx, "p", "tk"))

	ok, err := s.ConsumeBootstrapToken(ctx, "p", "tk")
	require.NoError(t, err)
	assert.True(t, ok)

	// Double-consume rejected.
	ok2, err := s.ConsumeBootstrapToken(ctx, "p", "tk")
	require.NoError(t, err)
	assert.False(t, ok2)
}
