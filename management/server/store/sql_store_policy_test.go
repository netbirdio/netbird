package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetPolicyByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		policyID    string
		expectError bool
	}{
		{
			name:        "retrieve existing policy",
			policyID:    "cs1tnh0hhcjnqoiuebf0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing policy checks",
			policyID:    "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty policy ID",
			policyID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, tt.policyID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, policy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy)
				require.Equal(t, tt.policyID, policy.ID)
			}
		})
	}
}

func TestSqlStore_GetPolicyByIDOrPublicID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policyID)
	require.NoError(t, err)
	require.NotEmpty(t, policy.PublicID)

	for _, id := range []string{policyID, policy.PublicID} {
		policy, err := store.GetPolicyByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, id)
		require.NoError(t, err)
		require.Equal(t, policyID, policy.ID)
	}

	policy, err = store.GetPolicyByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, "non-existing")
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, sErr.Type(), status.NotFound)
	require.Nil(t, policy)
}

func TestSqlStore_CreatePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	policy := &types.Policy{
		ID:        "policy-id",
		AccountID: accountID,
		Enabled:   true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupC"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}
	err = store.CreatePolicy(context.Background(), policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)

}

func TestSqlStore_SavePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policyID)
	require.NoError(t, err)

	policy.Enabled = false
	policy.Description = "policy"
	policy.Rules[0].Sources = []string{"group"}
	policy.Rules[0].Ports = []string{"80", "443"}
	err = store.SavePolicy(context.Background(), policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)
}

func TestSqlStore_DeletePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	err = store.DeletePolicy(context.Background(), accountID, policyID)
	require.NoError(t, err)

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policyID)
	require.Error(t, err)
	require.Nil(t, policy)
}
