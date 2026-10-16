package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetAccountNameServerGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve name server groups by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountNameServerGroups(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetNameServerByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		nsGroupID   string
		expectError bool
	}{
		{
			name:        "retrieve existing nameserver group",
			nsGroupID:   "csqdelq7qv97ncu7d9t0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing nameserver group",
			nsGroupID:   "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty nameserver group ID",
			nsGroupID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, tt.nsGroupID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, nsGroup)
			} else {
				require.NoError(t, err)
				require.NotNil(t, nsGroup)
				require.Equal(t, tt.nsGroupID, nsGroup.ID)
			}
		})
	}
}

func TestSqlStore_SaveNameServerGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	nsGroup := &nbdns.NameServerGroup{
		ID:        "ns-group-id",
		AccountID: accountID,
		Name:      "NS Group",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("8.8.8.8"),
				NSType: 1,
				Port:   53,
			},
		},
		Groups:               []string{"groupA"},
		Primary:              true,
		Enabled:              true,
		SearchDomainsEnabled: false,
	}

	err = store.SaveNameServerGroup(context.Background(), nsGroup)
	require.NoError(t, err)

	saveNSGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, nsGroup.ID)
	require.NoError(t, err)
	require.Equal(t, saveNSGroup, nsGroup)
}

func TestSqlStore_DeleteNameServerGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nsGroupID := "csqdelq7qv97ncu7d9t0"

	err = store.DeleteNameServerGroup(context.Background(), accountID, nsGroupID)
	require.NoError(t, err)

	nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, nsGroupID)
	require.Error(t, err)
	require.Nil(t, nsGroup)
}
