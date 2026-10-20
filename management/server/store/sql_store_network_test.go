package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetAccountNetworks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve networks by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},

		{
			name:          "retrieve networks by non-existing account ID",
			accountID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := store.GetAccountNetworks(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, networks, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		networkID   string
		expectError bool
	}{
		{
			name:        "retrieve existing network ID",
			networkID:   "ct286bi7qv930dsrrug0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing network ID",
			networkID:   "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve network with empty ID",
			networkID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, network)
			} else {
				require.NoError(t, err)
				require.NotNil(t, network)
				require.Equal(t, tt.networkID, network.ID)
			}
		})
	}
}

func TestSqlStore_SaveNetwork(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	network := &networkTypes.Network{
		ID:        "net-id",
		AccountID: accountID,
		Name:      "net",
	}

	err = store.SaveNetwork(context.Background(), network)
	require.NoError(t, err)

	savedNet, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, network.ID)
	require.NoError(t, err)
	require.Equal(t, network, savedNet)
}

func TestSqlStore_DeleteNetwork(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	err = store.DeleteNetwork(context.Background(), accountID, networkID)
	require.NoError(t, err)

	network, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, networkID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, network)
}
