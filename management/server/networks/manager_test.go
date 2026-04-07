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
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, groupsManager, &am, nil)
	manager := NewManager(s, resourcesManager, routerManager, &am)

	networks, err := manager.GetAllNetworks(ctx, accountID, userID)
	require.NoError(t, err)
	require.Len(t, networks, 1)
	require.Equal(t, "testNetworkId", networks[0].ID)
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
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, groupsManager, &am, nil)
	manager := NewManager(s, resourcesManager, routerManager, &am)

	networks, err := manager.GetNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
	require.Equal(t, "testNetworkId", networks.ID)
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
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, groupsManager, &am, nil)
	manager := NewManager(s, resourcesManager, routerManager, &am)

	createdNetwork, err := manager.CreateNetwork(ctx, userID, network)
	require.NoError(t, err)
	require.Equal(t, network.Name, createdNetwork.Name)
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
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, groupsManager, &am, nil)
	manager := NewManager(s, resourcesManager, routerManager, &am)

	err = manager.DeleteNetwork(ctx, accountID, userID, networkID)
	require.NoError(t, err)
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
	groupsManager := groups.NewManagerMock()
	routerManager := routers.NewManagerMock()
	resourcesManager := resources.NewManager(s, groupsManager, &am, nil)
	manager := NewManager(s, resourcesManager, routerManager, &am)

	updatedNetwork, err := manager.UpdateNetwork(ctx, userID, network)
	require.NoError(t, err)
	require.Equal(t, network.Name, updatedNetwork.Name)
}
