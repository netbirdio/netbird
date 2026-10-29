package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetNetworkRoutersByNetID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name          string
		networkID     string
		expectedCount int
	}{
		{
			name:          "retrieve routers by existing network ID",
			networkID:     "ct286bi7qv930dsrrug0",
			expectedCount: 1,
		},
		{
			name:          "retrieve routers by non-existing network ID",
			networkID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routers, err := store.GetNetworkRoutersByNetID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			require.NoError(t, err)
			require.Len(t, routers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkRouterByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name            string
		networkRouterID string
		expectError     bool
	}{
		{
			name:            "retrieve existing network router ID",
			networkRouterID: "ctc20ji7qv9ck2sebc80",
			expectError:     false,
		},
		{
			name:            "retrieve non-existing network router ID",
			networkRouterID: "non-existing",
			expectError:     true,
		},
		{
			name:            "retrieve network with empty router ID",
			networkRouterID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networkRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthNone, accountID, tt.networkRouterID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, networkRouter)
			} else {
				require.NoError(t, err)
				require.NotNil(t, networkRouter)
				require.Equal(t, tt.networkRouterID, networkRouter.ID)
			}
		})
	}
}

func TestSqlStore_CreateNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	netRouter, err := routerTypes.NewNetworkRouter(accountID, networkID, "", []string{"net-router-grp"}, true, 0, true)
	require.NoError(t, err)

	err = store.CreateNetworkRouter(context.Background(), netRouter)
	require.NoError(t, err)

	savedNetRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthNone, accountID, netRouter.ID)
	require.NoError(t, err)
	require.Equal(t, netRouter, savedNetRouter)
}

func TestSqlStore_UpdateNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"
	routerID := "ctc20ji7qv9ck2sebc80"

	netRouter := &routerTypes.NetworkRouter{
		ID:         routerID,
		AccountID:  accountID,
		NetworkID:  networkID,
		Peer:       "",
		PeerGroups: []string{"net-router-grp"},
		Masquerade: true,
		Metric:     42,
		Enabled:    true,
	}

	err = store.UpdateNetworkRouter(context.Background(), netRouter)
	require.NoError(t, err)

	savedNetRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthNone, accountID, routerID)
	require.NoError(t, err)
	require.Equal(t, netRouter, savedNetRouter)

	// Updating a router under a different account must not match any row.
	netRouter.AccountID = "non-existent-account"
	err = store.UpdateNetworkRouter(context.Background(), netRouter)
	require.Error(t, err)
}

func TestSqlStore_DeleteNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netRouterID := "ctc20ji7qv9ck2sebc80"

	err = store.DeleteNetworkRouter(context.Background(), accountID, netRouterID)
	require.NoError(t, err)

	netRouter, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, netRouterID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, netRouter)
}
