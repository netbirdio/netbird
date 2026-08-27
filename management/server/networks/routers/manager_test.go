package routers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func Test_GetAllRoutersInNetworkReturnsRouters(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
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
	userID := "testUserId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
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
	userID := "testAdminId"
	networkID := "testNetworkId"
	resourceID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	router, err := manager.GetRouter(ctx, accountID, userID, networkID, resourceID)
	require.NoError(t, err)
	require.Equal(t, "testRouterId", router.ID)
}

func Test_GetRouterReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"
	resourceID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	router, err := manager.GetRouter(ctx, accountID, userID, networkID, resourceID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, router)
}

func Test_CreateRouterSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 9999, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
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
	userID := "testUserId"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 9999, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
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
	userID := "testAdminId"
	networkID := "testNetworkId"
	routerID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	err = manager.DeleteRouter(ctx, accountID, userID, networkID, routerID)
	require.NoError(t, err)
}

func Test_DeleteRouterFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"
	routerID := "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	err = manager.DeleteRouter(ctx, accountID, userID, networkID, routerID)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
}

func Test_UpdateRouterSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}
	router.ID = "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.NoError(t, err)
	require.Equal(t, router.Metric, updatedRouter.Metric)
}

func Test_UpdateRouterRejectsCrossAccountID(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"

	// Admin of testAccountId tries to update a router that belongs to otherAccountId
	// by passing the other account's router ID through the URL.
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}
	router.ID = "otherRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Nil(t, updatedRouter)

	// The other account's router must be untouched.
	stored, err := s.GetNetworkRouterByID(ctx, store.LockingStrengthNone, "otherAccountId", "otherRouterId")
	require.NoError(t, err)
	require.Equal(t, "otherAccountId", stored.AccountID)
	require.Equal(t, "otherNetworkId", stored.NetworkID)
	require.Equal(t, "otherPeer", stored.Peer)
	require.Equal(t, 1, stored.Metric)
}

func Test_CreateRouterRejectsCrossAccountID(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"

	// Admin of testAccountId tries to create a router in otherAccountId's network.
	// The permission check is on router.AccountID (their own), but the network
	// lookup must fail because (testAccountId, otherNetworkId) does not exist.
	router, err := types.NewNetworkRouter("testAccountId", "otherNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	createdRouter, err := manager.CreateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Nil(t, createdRouter)

	// No router should have been created in either account's scope under otherNetworkId.
	routersInOther, err := s.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, "otherAccountId", "otherNetworkId")
	require.NoError(t, err)
	require.Len(t, routersInOther, 1)
	require.Equal(t, "otherRouterId", routersInOther[0].ID)
}

func Test_UpdateRouterRejectsNetworkMismatch(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"

	// The router exists in testNetworkId, but the caller submits secondNetworkId
	// (a different network in the same account). The update must be refused.
	router, err := types.NewNetworkRouter("testAccountId", "secondNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}
	router.ID = "testRouterId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Nil(t, updatedRouter)

	stored, err := s.GetNetworkRouterByID(ctx, store.LockingStrengthNone, "testAccountId", "testRouterId")
	require.NoError(t, err)
	require.Equal(t, "testNetworkId", stored.NetworkID)
}

func Test_UpdateRouterFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "testUserId"
	router, err := types.NewNetworkRouter("testAccountId", "testNetworkId", "testPeerId", []string{}, false, 1, true)
	if err != nil {
		require.NoError(t, err)
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	permissionsManager := permissions.NewManager(s)
	am := mock_server.MockAccountManager{}
	manager := NewManager(s, permissionsManager, &am)

	updatedRouter, err := manager.UpdateRouter(ctx, userID, router)
	require.Error(t, err)
	require.Equal(t, status.NewPermissionDeniedError(), err)
	require.Nil(t, updatedRouter)
}
