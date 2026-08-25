package networks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
)

func Test_GetAllNetworksReturnsNetworks(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	networks, err := manager.GetAllNetworks(ctx, accountID, userID)
	require.NoError(t, err)
	ids := make([]string, 0, len(networks))
	for _, n := range networks {
		ids = append(ids, n.ID)
	}
	require.ElementsMatch(t, []string{"testNetworkId", "secondNetworkId"}, ids)
}

func Test_GetAllNetworksReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	networks, err := manager.GetAllNetworks(ctx, accountID, userID)
	require.Error(t, err)
	require.Nil(t, networks)
}

func Test_GetNetworkReturnsNetwork(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	networks, err := manager.GetNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
	require.Equal(t, "testNetworkId", networks.ID)
}

func Test_GetNetworkReturnsPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	network, err := manager.GetNetwork(ctx, accountID, userID, networkID)
	require.Error(t, err)
	require.Nil(t, network)
}

func Test_CreateNetworkSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	network := &types.Network{
		AccountID: "testAccountId",
		Name:      "new-network",
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	createdNetwork, err := manager.CreateNetwork(ctx, userID, network)
	require.NoError(t, err)
	require.Equal(t, network.Name, createdNetwork.Name)
}

func Test_CreateNetworkFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "testUserId"
	network := &types.Network{
		AccountID: "testAccountId",
		Name:      "new-network",
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	createdNetwork, err := manager.CreateNetwork(ctx, userID, network)
	require.Error(t, err)
	require.Nil(t, createdNetwork)
}

func Test_DeleteNetworkSuccessfully(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testAdminId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	err = manager.DeleteNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
}

func Test_DeleteNetworkFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"
	userID := "testUserId"
	networkID := "testNetworkId"

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	err = manager.DeleteNetwork(ctx, accountID, userID, networkID)
	require.Error(t, err)
}

func Test_UpdateNetworkSuccessfully(t *testing.T) {
	ctx := context.Background()
	userID := "testAdminId"
	network := &types.Network{
		AccountID: "testAccountId",
		ID:        "testNetworkId",
		Name:      "new-network",
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)
	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	updatedNetwork, err := manager.UpdateNetwork(ctx, userID, network)
	require.NoError(t, err)
	require.Equal(t, network.Name, updatedNetwork.Name)
}

func Test_UpdateNetworkFailsWithPermissionDenied(t *testing.T) {
	ctx := context.Background()
	userID := "testUserId"
	network := &types.Network{
		AccountID: "testAccountId",
		ID:        "testNetworkId",
		Name:      "new-network",
	}

	s, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/networks.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	updatedNetwork, err := manager.UpdateNetwork(ctx, userID, network)
	require.Error(t, err)
	require.Nil(t, updatedNetwork)
}

// Test_CreateNetworkAllocatesSeqID verifies that CreateNetwork sets a
// non-zero AccountSeqID on the persisted network (allocated through the
// account_seq_counters table).
func Test_CreateNetworkSetsPublicId(t *testing.T) {
	ctx := context.Background()
	const accountID = "testAccountId"
	const userID = "testAdminId"

	s, cleanUp, err := store.NewTestStoreFromSQL(ctx, "../testdata/networks.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	created, err := manager.CreateNetwork(ctx, userID, &types.Network{
		AccountID: accountID,
		Name:      "seq-allocation-test",
	})
	require.NoError(t, err)
	require.NotEqual(t, "", created.PublicID, "CreateNetwork must allocate a non-zero AccountSeqID")
}

// Test_UpdateNetworkPreservesSeqID verifies UpdateNetwork does not reset
// AccountSeqID even when the caller passes a zero value (the shape REST
// handlers produce because the field is `json:"-"`).
func Test_UpdateNetworkPreservesPublicId(t *testing.T) {
	ctx := context.Background()
	const accountID = "testAccountId"
	const userID = "testAdminId"

	s, cleanUp, err := store.NewTestStoreFromSQL(ctx, "../testdata/networks.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, permissionsManager, groupsManager, &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routerManager, &am)

	created, err := manager.CreateNetwork(ctx, userID, &types.Network{
		AccountID: accountID,
		Name:      "seq-preserve-original",
	})
	require.NoError(t, err)
	originalPublicId := created.PublicID
	require.NotZero(t, originalPublicId)

	update := &types.Network{
		AccountID: accountID,
		ID:        created.ID,
		Name:      "seq-preserve-renamed",
	}
	require.Equal(t, "", update.PublicID, "incoming struct must mirror an HTTP handler shape")

	_, err = manager.UpdateNetwork(ctx, userID, update)
	require.NoError(t, err)

	got, err := manager.GetNetwork(ctx, accountID, userID, created.ID)
	require.NoError(t, err)
	require.Equal(t, originalPublicId, got.PublicID, "PublicID must survive UpdateNetwork")
	require.Equal(t, "seq-preserve-renamed", got.Name)
}
