package manager

import (
	"context"
	"fmt"
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
	testZoneID    = "test-zone-id"
	testGroupID   = "test-group-id"
	testDNSDomain = "netbird.selfhosted"
)

func setupTest(t *testing.T) (*managerImpl, store.Store, *mock_server.MockAccountManager, *permissions.MockManager, *gomock.Controller, func()) {
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

	ctrl := gomock.NewController(t)
	mockAccountManager := &mock_server.MockAccountManager{}
	mockPermissionsManager := permissions.NewMockManager(ctrl)

	manager := &managerImpl{
		store:              testStore,
		accountManager:     mockAccountManager,
		permissionsManager: mockPermissionsManager,
		dnsDomain:          testDNSDomain,
	}

	return manager, testStore, mockAccountManager, mockPermissionsManager, ctrl, cleanup
}

func TestManagerImpl_GetAllZones(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		zone1 := zones.NewZone(testAccountID, "Zone 1", "zone1.example.com", true, true, []string{testGroupID})
		err := testStore.CreateZone(ctx, zone1)
		require.NoError(t, err)

		zone2 := zones.NewZone(testAccountID, "Zone 2", "zone2.example.com", false, false, []string{testGroupID})
		err = testStore.CreateZone(ctx, zone2)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(true, nil)

		result, err := manager.GetAllZones(ctx, testAccountID, testUserID)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, zone1.ID, result[0].ID)
		assert.Equal(t, zone2.ID, result[1].ID)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, nil)

		result, err := manager.GetAllZones(ctx, testAccountID, testUserID)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("permission validation error", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, status.Errorf(status.Internal, "permission check failed"))

		result, err := manager.GetAllZones(ctx, testAccountID, testUserID)
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestManagerImpl_GetZone(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		zone := zones.NewZone(testAccountID, "Test Zone", "test.example.com", true, true, []string{testGroupID})
		err := testStore.CreateZone(ctx, zone)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(true, nil)

		result, err := manager.GetZone(ctx, testAccountID, testUserID, zone.ID)
		require.NoError(t, err)
		assert.Equal(t, zone.ID, result.ID)
		assert.Equal(t, zone.Name, result.Name)
		assert.Equal(t, zone.Domain, result.Domain)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Read).
			Return(false, nil)

		result, err := manager.GetZone(ctx, testAccountID, testUserID, testZoneID)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})
}

func TestManagerImpl_CreateZone(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, _, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputZone := &zones.Zone{
			Name:               "New Zone",
			Domain:             "new.example.com",
			Enabled:            true,
			EnableSearchDomain: true,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSZoneCreated, activityID)
		}

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.ID)
		assert.Equal(t, testAccountID, result.AccountID)
		assert.Equal(t, inputZone.Name, result.Name)
		assert.Equal(t, inputZone.Domain, result.Domain)
		assert.Equal(t, inputZone.Enabled, result.Enabled)
		assert.Equal(t, inputZone.EnableSearchDomain, result.EnableSearchDomain)
		assert.Equal(t, inputZone.DistributionGroups, result.DistributionGroups)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputZone := &zones.Zone{
			Name:               "New Zone",
			Domain:             "new.example.com",
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(false, nil)

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("invalid group", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputZone := &zones.Zone{
			Name:               "New Zone",
			Domain:             "new.example.com",
			DistributionGroups: []string{"invalid-group"},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("duplicate domain", func(t *testing.T) {
		manager, testStore, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingZone := zones.NewZone(testAccountID, "Existing Zone", "duplicate.example.com", true, false, []string{testGroupID})
		err := testStore.CreateZone(ctx, existingZone)
		require.NoError(t, err)

		inputZone := &zones.Zone{
			Name:               "New Zone",
			Domain:             "duplicate.example.com",
			Enabled:            true,
			EnableSearchDomain: false,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "zone with domain duplicate.example.com already exists")
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.AlreadyExists, s.Type())
	})

	t.Run("peer DNS domain conflict", func(t *testing.T) {
		manager, testStore, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		account, err := testStore.GetAccount(ctx, testAccountID)
		require.NoError(t, err)
		account.Settings.DNSDomain = "peers.example.com"
		err = testStore.SaveAccount(ctx, account)
		require.NoError(t, err)

		inputZone := &zones.Zone{
			Name:               "Test Zone",
			Domain:             "peers.example.com",
			Enabled:            true,
			EnableSearchDomain: false,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "zone domain peers.example.com conflicts with peer DNS domain")
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.InvalidArgument, s.Type())
	})

	t.Run("default DNS domain conflict", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		inputZone := &zones.Zone{
			Name:               "Test Zone",
			Domain:             testDNSDomain,
			Enabled:            true,
			EnableSearchDomain: false,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Create).
			Return(true, nil)

		result, err := manager.CreateZone(ctx, testAccountID, testUserID, inputZone)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), fmt.Sprintf("zone domain %s conflicts with peer DNS domain", testDNSDomain))
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.InvalidArgument, s.Type())
	})
}

func TestManagerImpl_UpdateZone(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		manager, testStore, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingZone := zones.NewZone(testAccountID, "Old Name", "example.com", false, false, []string{testGroupID})
		err := testStore.CreateZone(ctx, existingZone)
		require.NoError(t, err)

		updatedZone := &zones.Zone{
			ID:                 existingZone.ID,
			Name:               "Updated Name",
			Domain:             "example.com",
			Enabled:            true,
			EnableSearchDomain: true,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		storeEventCalled := false
		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			storeEventCalled = true
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, existingZone.ID, targetID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSZoneUpdated, activityID)
		}

		result, err := manager.UpdateZone(ctx, testAccountID, testUserID, updatedZone)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, updatedZone.Name, result.Name)
		assert.Equal(t, updatedZone.Enabled, result.Enabled)
		assert.Equal(t, updatedZone.EnableSearchDomain, result.EnableSearchDomain)
		assert.True(t, storeEventCalled, "StoreEvent should have been called")
	})

	t.Run("domain change not allowed", func(t *testing.T) {
		manager, testStore, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		existingZone := zones.NewZone(testAccountID, "Test Zone", "example.com", true, true, []string{testGroupID})
		err := testStore.CreateZone(ctx, existingZone)
		require.NoError(t, err)

		updatedZone := &zones.Zone{
			ID:                 existingZone.ID,
			Name:               "Test Zone",
			Domain:             "different.com",
			Enabled:            true,
			EnableSearchDomain: true,
			DistributionGroups: []string{testGroupID},
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		result, err := manager.UpdateZone(ctx, testAccountID, testUserID, updatedZone)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "zone domain cannot be updated")
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.InvalidArgument, s.Type())
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		updatedZone := &zones.Zone{
			ID:     testZoneID,
			Name:   "Updated Name",
			Domain: "example.com",
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(false, nil)

		result, err := manager.UpdateZone(ctx, testAccountID, testUserID, updatedZone)
		require.Error(t, err)
		assert.Nil(t, result)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("zone not found", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		updatedZone := &zones.Zone{
			ID:     "non-existent-zone",
			Name:   "Updated Name",
			Domain: "example.com",
		}

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Update).
			Return(true, nil)

		result, err := manager.UpdateZone(ctx, testAccountID, testUserID, updatedZone)
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestManagerImpl_DeleteZone(t *testing.T) {
	ctx := context.Background()

	t.Run("success with records", func(t *testing.T) {
		manager, testStore, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		zone := zones.NewZone(testAccountID, "Test Zone", "example.com", true, true, []string{testGroupID})
		err := testStore.CreateZone(ctx, zone)
		require.NoError(t, err)

		record1 := records.NewRecord(testAccountID, zone.ID, "api.example.com", records.RecordTypeA, "192.168.1.1", 300)
		err = testStore.CreateDNSRecord(ctx, record1)
		require.NoError(t, err)

		record2 := records.NewRecord(testAccountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.2", 300)
		err = testStore.CreateDNSRecord(ctx, record2)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(true, nil)

		storeEventCallCount := 0
		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			storeEventCallCount++
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, testAccountID, accountID)
		}

		err = manager.DeleteZone(ctx, testAccountID, testUserID, zone.ID)
		require.NoError(t, err)
		assert.Equal(t, 3, storeEventCallCount)

		_, err = testStore.GetZoneByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID)
		require.Error(t, err)

		zoneRecords, err := testStore.GetZoneDNSRecords(ctx, store.LockingStrengthNone, testAccountID, zone.ID)
		require.NoError(t, err)
		assert.Empty(t, zoneRecords)
	})

	t.Run("success without records", func(t *testing.T) {
		manager, testStore, mockAccountManager, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		zone := zones.NewZone(testAccountID, "Test Zone", "example.com", true, true, []string{testGroupID})
		err := testStore.CreateZone(ctx, zone)
		require.NoError(t, err)

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(true, nil)

		storeEventCalled := false
		mockAccountManager.StoreEventFunc = func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
			storeEventCalled = true
			assert.Equal(t, testUserID, initiatorID)
			assert.Equal(t, zone.ID, targetID)
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, activity.DNSZoneDeleted, activityID)
		}

		err = manager.DeleteZone(ctx, testAccountID, testUserID, zone.ID)
		require.NoError(t, err)
		assert.True(t, storeEventCalled, "StoreEvent should have been called")

		_, err = testStore.GetZoneByID(ctx, store.LockingStrengthNone, testAccountID, zone.ID)
		require.Error(t, err)
	})

	t.Run("permission denied", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(false, nil)

		err := manager.DeleteZone(ctx, testAccountID, testUserID, testZoneID)
		require.Error(t, err)
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, status.PermissionDenied, s.Type())
	})

	t.Run("zone not found", func(t *testing.T) {
		manager, _, _, mockPermissionsManager, ctrl, cleanup := setupTest(t)
		defer cleanup()
		defer ctrl.Finish()

		mockPermissionsManager.EXPECT().
			ValidateUserPermissions(ctx, testAccountID, testUserID, modules.Dns, operations.Delete).
			Return(true, nil)

		err := manager.DeleteZone(ctx, testAccountID, testUserID, "non-existent-zone")
		require.Error(t, err)
	})
}
