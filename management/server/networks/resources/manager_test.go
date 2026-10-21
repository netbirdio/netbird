package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	reverseproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func Test_GetAllResourcesInNetworkReturnsResources(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resources, err := manager.GetAllResourcesInNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
	require.Len(t, resources, 2)
}

func Test_GetAllResourcesInNetworkReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resources, err := manager.GetAllResourcesInNetwork(ctx, accountID, userID, networkID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, resources)
}
func Test_GetAllResourcesInAccountReturnsResources(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resources, err := manager.GetAllResourcesInAccount(ctx, accountID, userID)
	require.NoError(t, err)
	require.Len(t, resources, 2)
}

func Test_GetAllResourcesInAccountReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resources, err := manager.GetAllResourcesInAccount(ctx, accountID, userID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, resources)
}

func Test_GetResourceInNetworkReturnsResources(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resource, err := manager.GetResource(ctx, accountID, userID, networkID, resourceID)
	require.NoError(t, err)
	require.Equal(t, resourceID, resource.ID)
}

func Test_GetResourceInNetworkReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	resources, err := manager.GetResource(ctx, accountID, userID, networkID, resourceID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, resources)
}

func Test_CreateResourceSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	resource := &types.NetworkResource{
		AccountID:   "testAccountId",
		NetworkID:   "testNetworkId",
		Name:        "newResourceId",
		Description: "description",
		Address:     "192.168.1.1",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	serviceManager.EXPECT().ReloadAllServicesForAccount(gomock.Any(), resource.AccountID).Return(nil).AnyTimes()
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	createdResource, err := manager.CreateResource(ctx, userID, resource)
	require.NoError(t, err)
	require.Equal(t, resource.Name, createdResource.Name)
}

func Test_CreateResourceFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "testUserId"
	resource := &types.NetworkResource{
		AccountID:   "testAccountId",
		NetworkID:   "testNetworkId",
		Name:        "testResourceId",
		Description: "description",
		Address:     "192.168.1.1",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	createdResource, err := manager.CreateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, createdResource)
}

func Test_CreateResourceFailsWithInvalidAddress(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	resource := &types.NetworkResource{
		AccountID:   "testAccountId",
		NetworkID:   "testNetworkId",
		Name:        "testResourceId",
		Description: "description",
		Address:     "-invalid",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	createdResource, err := manager.CreateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Nil(t, createdResource)
}

func Test_CreateResourceFailsWithUsedName(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	resource := &types.NetworkResource{
		AccountID:   "testAccountId",
		NetworkID:   "testNetworkId",
		Name:        "used-name",
		Description: "description",
		Address:     "example.com",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	createdResource, err := manager.CreateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Nil(t, createdResource)
}

func Test_UpdateResourceSuccessfully(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"
	resource := &types.NetworkResource{
		AccountID:   accountID,
		NetworkID:   networkID,
		Name:        "someNewName",
		ID:          resourceID,
		Description: "new-description",
		Address:     "1.2.3.0/24",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	serviceManager.EXPECT().ReloadAllServicesForAccount(gomock.Any(), accountID).Return(nil).AnyTimes()
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	updatedResource, err := manager.UpdateResource(ctx, userID, resource)
	require.NoError(t, err)
	require.NotNil(t, updatedResource)
	require.Equal(t, "new-description", updatedResource.Description)
	require.Equal(t, "1.2.3.0/24", updatedResource.Address)
	require.Equal(t, types.NetworkResourceType("subnet"), updatedResource.Type)
}

func Test_UpdateResourceFailsWithResourceNotFound(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "otherResourceId"
	resource := &types.NetworkResource{
		AccountID:   accountID,
		NetworkID:   networkID,
		Name:        resourceID,
		Description: "new-description",
		Address:     "1.2.3.0/24",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	updatedResource, err := manager.UpdateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Nil(t, updatedResource)
}

func Test_UpdateResourceFailsWithNameInUse(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"
	resource := &types.NetworkResource{
		AccountID:   accountID,
		NetworkID:   networkID,
		ID:          resourceID,
		Name:        "used-name",
		Description: "new-description",
		Address:     "1.2.3.0/24",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	updatedResource, err := manager.UpdateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Nil(t, updatedResource)
}

func Test_UpdateResourceFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"
	resource := &types.NetworkResource{
		AccountID:   accountID,
		NetworkID:   networkID,
		Name:        resourceID,
		Description: "new-description",
		Address:     "1.2.3.0/24",
	}

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	updatedResource, err := manager.UpdateResource(ctx, userID, resource)
	require.Error(t, err)
	require.Nil(t, updatedResource)
}

func Test_DeleteResourceSuccessfully(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	serviceManager.EXPECT().GetServiceIDByTargetID(gomock.Any(), accountID, resourceID).Return("", nil).AnyTimes()
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	err = manager.DeleteResource(ctx, accountID, userID, networkID, resourceID)
	require.NoError(t, err)
}

func Test_DeleteResourceFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"
	resourceID := "testResourceId"

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(store)
	am := mock_server.MockAccountManager{}
	groupsManager := groups.NewManagerMock()
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	manager := NewManager(store, permissionsManager, groupsManager, &am, serviceManager)

	err = manager.DeleteResource(ctx, accountID, userID, networkID, resourceID)
	require.Error(t, err)
}

func Test_UpdateResourceUnchangedSkipsWriteButStoresEvent(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	newResource := func() *types.NetworkResource {
		return &types.NetworkResource{
			AccountID:   accountID,
			NetworkID:   "testNetworkId",
			Name:        "someNewName",
			ID:          "testResourceId",
			Description: "new-description",
			Address:     "1.2.3.0/24",
			Enabled:     true,
		}
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(ctx, "../../testdata/networks.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	var events, propagations int
	am := mock_server.MockAccountManager{
		StoreEventFunc: func(context.Context, string, string, string, activity.ActivityDescriber, map[string]any) {
			events++
		},
		ExpandAndUpdateAffectedFunc: func(context.Context, string, *affectedpeers.Snapshot, affectedpeers.Change) {
			propagations++
		},
	}
	ctrl := gomock.NewController(t)
	serviceManager := reverseproxy.NewMockManager(ctrl)
	serviceManager.EXPECT().ReloadAllServicesForAccount(gomock.Any(), accountID).Return(nil).AnyTimes()
	manager := NewManager(s, permissions.NewManager(s), groups.NewManagerMock(), &am, serviceManager)

	_, err = manager.UpdateResource(ctx, userID, newResource())
	require.NoError(t, err)
	require.Equal(t, 1, events, "first update should store an event")
	require.Equal(t, 1, propagations, "first update should propagate to peers")

	serialBefore, err := s.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)

	updated, err := manager.UpdateResource(ctx, userID, newResource())
	require.NoError(t, err)
	assert.NotEmpty(t, updated.PublicID, "returned resource should carry the stored public ID")
	assert.Equal(t, 2, events, "unchanged update should still store an activity event")
	assert.Equal(t, 1, propagations, "unchanged update should not propagate to peers")

	serialAfter, err := s.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	assert.Equal(t, serialBefore.Serial, serialAfter.Serial, "unchanged update should not bump the network serial")
}
