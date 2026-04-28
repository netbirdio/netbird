package manager

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testServiceID      = "test-service-id"
	testOtherServiceID = "test-other-service-id"
)

func TestAutoCreateForService_HappyPath(t *testing.T) {
	ctx := context.Background()
	_, testStore, zone, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	rec, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", net.ParseIP("10.0.0.42"))
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, testServiceID, rec.ManagedByServiceID)
	assert.Equal(t, "svc.example.com", rec.Name)
	assert.Equal(t, records.RecordTypeA, rec.Type)
	assert.Equal(t, "10.0.0.42", rec.Content)
	assert.Equal(t, zone.ID, rec.ZoneID)

	// Confirm persistence.
	saved, err := testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, testServiceID, saved.ManagedByServiceID)
}

func TestAutoCreateForService_IPv6PicksAAAA(t *testing.T) {
	ctx := context.Background()
	_, testStore, _, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	rec, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", net.ParseIP("fd00::1"))
	require.NoError(t, err)
	assert.Equal(t, records.RecordTypeAAAA, rec.Type)
}

func TestAutoCreateForService_RejectsUserManagedConflict(t *testing.T) {
	ctx := context.Background()
	_, testStore, zone, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	manual := records.NewRecord(testAccountID, zone.ID, "svc.example.com", records.RecordTypeA, "192.0.2.1", 300)
	require.NoError(t, testStore.CreateDNSRecord(ctx, manual))

	_, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	s, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, status.AlreadyExists, s.Type())
	assert.Contains(t, err.Error(), "user-managed")
}

func TestAutoCreateForService_RejectsOtherServiceConflict(t *testing.T) {
	ctx := context.Background()
	_, testStore, zone, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	owned := records.NewRecord(testAccountID, zone.ID, "svc.example.com", records.RecordTypeA, "192.0.2.1", 300)
	owned.ManagedByServiceID = testOtherServiceID
	require.NoError(t, testStore.CreateDNSRecord(ctx, owned))

	_, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	s, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, status.AlreadyExists, s.Type())
	assert.Contains(t, err.Error(), testOtherServiceID)
}

func TestAutoCreateForService_NoMatchingZone(t *testing.T) {
	ctx := context.Background()
	_, testStore, _, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	_, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.unknown.tld", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	s, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, status.InvalidArgument, s.Type())
	assert.Contains(t, err.Error(), "no DNS zone configured")
}

func TestAutoCreateForService_LongestSuffixMatch(t *testing.T) {
	ctx := context.Background()
	_, testStore, _, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	devZone := zones.NewZone(testAccountID, "Dev Zone", "dev.example.com", true, true, []string{testGroupID})
	require.NoError(t, testStore.CreateZone(ctx, devZone))

	rec, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.dev.example.com", net.ParseIP("10.0.0.42"))
	require.NoError(t, err)
	assert.Equal(t, devZone.ID, rec.ZoneID, "should land in dev.example.com, not example.com")
}

func TestAutoDeleteForService_Idempotent(t *testing.T) {
	ctx := context.Background()
	_, testStore, _, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	// No record exists; first call is a no-op.
	require.NoError(t, AutoDeleteForService(ctx, testStore, testAccountID, testServiceID))

	// Create a managed record, then delete; second delete is a no-op.
	_, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", net.ParseIP("10.0.0.42"))
	require.NoError(t, err)
	require.NoError(t, AutoDeleteForService(ctx, testStore, testAccountID, testServiceID))
	require.NoError(t, AutoDeleteForService(ctx, testStore, testAccountID, testServiceID))
}

func TestAutoDeleteForService_OnlyDeletesOwn(t *testing.T) {
	ctx := context.Background()
	_, testStore, zone, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	manual := records.NewRecord(testAccountID, zone.ID, "manual.example.com", records.RecordTypeA, "192.0.2.1", 300)
	require.NoError(t, testStore.CreateDNSRecord(ctx, manual))

	otherSvc := records.NewRecord(testAccountID, zone.ID, "other.example.com", records.RecordTypeA, "192.0.2.2", 300)
	otherSvc.ManagedByServiceID = testOtherServiceID
	require.NoError(t, testStore.CreateDNSRecord(ctx, otherSvc))

	mine, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "mine.example.com", net.ParseIP("10.0.0.42"))
	require.NoError(t, err)

	require.NoError(t, AutoDeleteForService(ctx, testStore, testAccountID, testServiceID))

	// Manual + other-service records remain; mine is gone.
	_, err = testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, manual.ID)
	require.NoError(t, err)
	_, err = testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, otherSvc.ID)
	require.NoError(t, err)
	_, err = testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, mine.ID)
	require.Error(t, err)
}

func TestAutoUpdateForService_DeleteOldCreateNew(t *testing.T) {
	ctx := context.Background()
	_, testStore, zone, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	old, err := AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "old.example.com", net.ParseIP("10.0.0.42"))
	require.NoError(t, err)

	updated, err := AutoUpdateForService(ctx, testStore, testAccountID, testServiceID, "new.example.com", net.ParseIP("10.0.0.99"))
	require.NoError(t, err)
	assert.NotEqual(t, old.ID, updated.ID, "AutoUpdate creates a fresh record")
	assert.Equal(t, "new.example.com", updated.Name)
	assert.Equal(t, "10.0.0.99", updated.Content)

	_, err = testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, old.ID)
	require.Error(t, err, "old record should be gone")
}

func TestAutoCreateForService_RequiresArgs(t *testing.T) {
	ctx := context.Background()
	_, testStore, _, _, _, ctrl, cleanup := setupTest(t)
	defer cleanup()
	defer ctrl.Finish()

	_, err := AutoCreateForService(ctx, testStore, "", testServiceID, "svc.example.com", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	_, err = AutoCreateForService(ctx, testStore, testAccountID, "", "svc.example.com", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	_, err = AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "", net.ParseIP("10.0.0.42"))
	require.Error(t, err)
	_, err = AutoCreateForService(ctx, testStore, testAccountID, testServiceID, "svc.example.com", nil)
	require.Error(t, err)
}
