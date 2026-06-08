package manager

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "test-account-id"
	testUserID    = "test-user-id"
	testRecordID  = "test-record-id"
	testGroupID   = "test-group-id"
)

func setupTest(t *testing.T) (*managerImpl, store.Store, *zones.Zone, *mock_server.MockAccountManager, *permissions.MockManager, *gomock.Controller, func()) {
	t.Helper()

	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)

	err = testStore.SaveAccount(ctx, &types.Account{
		Id: testAccountID,
		Groups: map[string]*types.Group{
			testGroupID: {
				ID:   testGroupID,
				Name: "Test Group",
			},
		},
	})
	require.NoError(t, err)

	zone := zones.NewZone(testAccountID, "Test Zone", "example.com", true, true, []string{testGroupID})
	err = testStore.CreateZone(ctx, zone)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	mockAccountManager := &mock_server.MockAccountManager{}
	mockPermissionsManager := permissions.NewMockManager(ctrl)

	manager := &managerImpl{
		store:              testStore,
		accountManager:     mockAccountManager,
		permissionsManager: mockPermissionsManager,
	}

	return manager, testStore, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup
}

func TestManagerImpl_GetAllRecords(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		record1 := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, record1)
		require.NoError(t, err)

		record2 := records.NewRecord(testAccountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.2", 300)
		err = testStore.CreateDNSRecord(ctx, record2)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(true, nil)

		result, err := manager.GetAllRecords(ctx, testAccountID, testUserID, zone.ID)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, record1.ID, result[0].ID)
		assert.Equal(t, record2.ID, result[1].ID)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, nil)

		result, err := manager.GetAllRecords(ctx, testAccountID, testUserID, zone.ID)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("permission validation error", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, status.Errorf(status.Internal, "permission check failed"))

		result, err := manager.GetAllRecords(ctx, testAccountID, testUserID, zone.ID)
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestManagerImpl_GetRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		record := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, record)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(true, nil)

		result, err := manager.GetRecord(ctx, testAccountID, testUserID, zone.ID, record.ID)
		require.NoError(t, err)
		assert.Equal(t, record.ID, result.ID)
		assert.Equal(t, record.Name, result.Name)
		assert.Equal(t, record.Type, result.Type)
		assert.Equal(t, record.Content, result.Content)
		assert.Equal(t, record.TTL, result.TTL)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, nil)

		result, err := manager.GetRecord(ctx, testAccountID, testUserID, zone.ID, testRecordID)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})
}

func TestManagerImpl_CreateRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("success - A record", func(t *testing.T) {
		manager, _, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputRecord := &records.Record{
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.1",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSRecordCreated, activityID)
		}

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.ID)
		assert.Equal(t, testAccountID, result.AccountID)
		assert.Equal(t, zone.ID, result.ZoneID)
		assert.Equal(t, inputRecord.Name, result.Name)
		assert.Equal(t, inputRecord.Type, result.Type)
		assert.Equal(t, inputRecord.Content, result.Content)
		assert.Equal(t, inputRecord.TTL, result.TTL)
	})

	t.Run("success - AAAA record", func(t *testing.T) {
		manager, _, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputRecord := &records.Record{
			Name:    "ipv6.example.com",
			Type:    records.RecordTypeAAAA,
			Content: "2001:db8::1",
			TTL:     600,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSRecordCreated, activityID)
		}

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, inputRecord.Type, result.Type)
		assert.Equal(t, inputRecord.Content, result.Content)
	})

	t.Run("success - CNAME record", func(t *testing.T) {
		manager, _, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputRecord := &records.Record{
			Name:    "www.example.com",
			Type:    records.RecordTypeCNAME,
			Content: "example.com",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSRecordCreated, activityID)
		}

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, inputRecord.Type, result.Type)
		assert.Equal(t, inputRecord.Content, result.Content)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputRecord := &records.Record{
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.1",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(false, nil)

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("record name not in zone", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputRecord := &records.Record{
			Name:    "api.different.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.1",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not belong to zone")
	})

	t.Run("duplicate record", func(t *testing.T) {
		manager, testStore, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingRecord := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, existingRecord)
		require.NoError(t, err)

		inputRecord := &records.Record{
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.1",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "identical record already exists")
	})

	t.Run("CNAME conflict with existing A record", func(t *testing.T) {
		manager, testStore, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingRecord := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, existingRecord)
		require.NoError(t, err)

		inputRecord := &records.Record{
			Name:    "api.example.com",
			Type:    records.RecordTypeCNAME,
			Content: "example.com",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateRecord(ctx, testAccountID, testUserID, zone.ID, inputRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestManagerImpl_UpdateRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingRecord := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, existingRecord)
		require.NoError(t, err)

		updatedRecord := &records.Record{
			ID:      existingRecord.ID,
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.100", // Changed IP
			TTL:     600,             // Changed TTL
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		storeEventCalled := false
		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			storeEventCalled = true
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, existingRecord.ID, targetID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSRecordUpdated, activityID)
		}

		result, err := manager.UpdateRecord(ctx, testAccountID, testUserID, zone.ID, updatedRecord)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, updatedRecord.Content, result.Content)
		assert.Equal(t, updatedRecord.TTL, result.TTL)
		assert.True(t, storeEventCalled, "StoreEvent should have been called")
	})

	t.Run("update only TTL - no validation", func(t *testing.T) {
		manager, testStore, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingRecord := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, existingRecord)
		require.NoError(t, err)

		updatedRecord := &records.Record{
			ID:      existingRecord.ID,
			Name:    existingRecord.Name,
			Type:    existingRecord.Type,
			Content: existingRecord.Content,
			TTL:     600, // Only TTL changed
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			// Event should be stored
		}

		result, err := manager.UpdateRecord(ctx, testAccountID, testUserID, zone.ID, updatedRecord)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 600, result.TTL)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		updatedRecord := &records.Record{
			ID:      testRecordID,
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.100",
			TTL:     600,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(false, nil)

		result, err := manager.UpdateRecord(ctx, testAccountID, testUserID, zone.ID, updatedRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("record not found", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		updatedRecord := &records.Record{
			ID:      "non-existent-record",
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.100",
			TTL:     600,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		result, err := manager.UpdateRecord(ctx, testAccountID, testUserID, zone.ID, updatedRecord)
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("update creates duplicate", func(t *testing.T) {
		manager, testStore, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		record1 := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, record1)
		require.NoError(t, err)

		record2 := records.NewRecord(testAccountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.2", 300)
		err = testStore.CreateDNSRecord(ctx, record2)
		require.NoError(t, err)

		updatedRecord := &records.Record{
			ID:      record2.ID,
			Name:    "api.example.com",
			Type:    records.RecordTypeA,
			Content: "192.168.1.1",
			TTL:     300,
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		result, err := manager.UpdateRecord(ctx, testAccountID, testUserID, zone.ID, updatedRecord)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "identical record already exists")
	})
}

func TestManagerImpl_DeleteRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, zone, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		record := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err := testStore.CreateDNSRecord(ctx, record)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(true, nil)

		storeEventCalled := false
		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			storeEventCalled = true
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, record.ID, targetID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSRecordDeleted, activityID)
		}

		err = manager.DeleteRecord(ctx, testAccountID, testUserID, zone.ID, record.ID)
		require.NoError(t, err)
		assert.True(t, storeEventCalled, "StoreEvent should have been called")

		_, err = testStore.GetDNSRecordByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID, record.ID)
		require.Error(t, err)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(false, nil)

		err := manager.DeleteRecord(ctx, testAccountID, testUserID, zone.ID, testRecordID)
		require.Error(t, err)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("record not found", func(t *testing.T) {
		manager, _, zone, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(true, nil)

		err := manager.DeleteRecord(ctx, testAccountID, testUserID, zone.ID, "non-existent-record")
		require.Error(t, err)
	})
}
