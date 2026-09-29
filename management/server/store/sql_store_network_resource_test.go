package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetNetworkResourcesByNetID(t *testing.T) {
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
			name:          "retrieve resources by existing network ID",
			networkID:     "ct286bi7qv930dsrrug0",
			expectedCount: 1,
		},
		{
			name:          "retrieve resources by non-existing network ID",
			networkID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netResources, err := store.GetNetworkResourcesByNetID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			require.NoError(t, err)
			require.Len(t, netResources, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkResourceByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name          string
		netResourceID string
		expectError   bool
	}{
		{
			name:          "retrieve existing network resource ID",
			netResourceID: "ctc4nci7qv9061u6ilfg",
			expectError:   false,
		},
		{
			name:          "retrieve non-existing network resource ID",
			netResourceID: "non-existing",
			expectError:   true,
		},
		{
			name:          "retrieve network with empty resource ID",
			netResourceID: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthNone, accountID, tt.netResourceID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, netResource)
			} else {
				require.NoError(t, err)
				require.NotNil(t, netResource)
				require.Equal(t, tt.netResourceID, netResource.ID)
			}
		})
	}
}

func TestSqlStore_GetNetworkResourceByIDOrPublicID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netResourceID := "ctc4nci7qv9061u6ilfg"

	netResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthNone, accountID, netResourceID)
	require.NoError(t, err)
	require.NotEmpty(t, netResource.PublicID)

	for _, id := range []string{netResourceID, netResource.PublicID} {
		netResource, err := store.GetNetworkResourceByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, id)
		require.NoError(t, err)
		require.Equal(t, netResourceID, netResource.ID)
	}

	netResource, err = store.GetNetworkResourceByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, "non-existing")
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, sErr.Type(), status.NotFound)
	require.Nil(t, netResource)
}

func TestSqlStore_SaveNetworkResource(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	netResource, err := resourceTypes.NewNetworkResource(accountID, networkID, "resource-name", "", "example.com", []string{}, true)
	require.NoError(t, err)

	err = store.SaveNetworkResource(context.Background(), netResource)
	require.NoError(t, err)

	savedNetResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthNone, accountID, netResource.ID)
	require.NoError(t, err)
	require.Equal(t, netResource.ID, savedNetResource.ID)
	require.Equal(t, netResource.Name, savedNetResource.Name)
	require.Equal(t, netResource.NetworkID, savedNetResource.NetworkID)
	require.Equal(t, netResource.Type, resourceTypes.NetworkResourceType("domain"))
	require.Equal(t, netResource.Domain, "example.com")
	require.Equal(t, netResource.AccountID, savedNetResource.AccountID)
	require.Equal(t, netResource.Prefix, netip.Prefix{})
}

func TestSqlStore_DeleteNetworkResource(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netResourceID := "ctc4nci7qv9061u6ilfg"

	err = store.DeleteNetworkResource(context.Background(), accountID, netResourceID)
	require.NoError(t, err)

	netResource, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, netResourceID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, netResource)
}
