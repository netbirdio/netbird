package routers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
)

func Test_GetAllRoutersInNetworkReturnsRouters(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "allowedUser"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	routers, err := manager.GetAllRoutersInNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
	require.Len(t, routers, 1)
	require.Equal(t, "testRouterId", routers[0].ID)
}

func Test_GetAllRoutersInNetworkReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "invalidUser"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	routers, err := manager.GetAllRoutersInNetwork(ctx, accountID, userID, networkID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, routers)
}

func Test_GetRouterReturnsRouter(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "allowedUser"
	networkID := "testNetworkId"
	resourceID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	router, err := manager.GetRouter(ctx, accountID, userID, networkID, resourceID)
	require.NoError(t, err)
	require.Equal(t, "testRouterId", router.ID)
}

func Test_GetRouterReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "invalidUser"
	networkID := "testNetworkId"
	resourceID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	router, err := manager.GetRouter(ctx, accountID, userID, networkID, resourceID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, router)
}

func Test_CreateRouterSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "allowedUser"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 9999, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	createdRouter, err := manager.CreateRouter(ctx, userID, router)
	require.NoError(t, err)
	require.NotEqual(t, "", router.ID)
	require.Equal(t, router.NetworkID, createdRouter.NetworkID)
	require.Equal(t, router.Peer, createdRouter.Peer)
	require.Equal(t, router.Metric, createdRouter.Metric)
	require.Equal(t, router.Masquerade, createdRouter.Masquerade)
}

func Test_CreateRouterFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "invalidUser"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 9999, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	createdRouter, err := manager.CreateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, createdRouter)
}

func Test_DeleteRouterSuccessfully(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "allowedUser"
	networkID := "testNetworkId"
	routerID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	err = manager.DeleteRouter(ctx, accountID, userID, networkID, routerID)
	require.NoError(t, err)
}

func Test_DeleteRouterFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "invalidUser"
	networkID := "testNetworkId"
	routerID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	err = manager.DeleteRouter(ctx, accountID, userID, networkID, routerID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
}

func Test_UpdateRouterSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "allowedUser"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.NoError(t, err)
	require.Equal(t, router.Metric, updatedRouter.Metric)
}

func Test_UpdateRouterFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "invalidUser"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManagerMock()
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, updatedRouter)
}
