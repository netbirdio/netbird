package store

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlStore_InspectionPolicyCRUD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "test-account-inspection"

		// Create account first
		account := newAccountWithId(ctx, accountID, "test-user", "example.com")
		err := store.SaveAccount(ctx, account)
		require.NoError(t, err)

		// Create
		policy := &types.InspectionPolicy{
			ID:          "ip-1",
			AccountID:   accountID,
			Name:        "Block gambling",
			Description: "Block all gambling sites",
			Enabled:     true,
			Rules: []types.InspectionPolicyRule{
				{
					Domains:   []string{"*.gambling.com", "*.betting.com"},
					Action:    "block",
					Priority:  1,
					Protocols: []string{"https"},
				},
				{
					Domains:  []string{"*.malware.org"},
					Networks: []string{"10.0.0.0/8"},
					Action:   "block",
					Priority: 2,
				},
			},
		}
		err = store.SaveInspectionPolicy(ctx, LockingStrengthUpdate, policy)
		require.NoError(t, err)

		// Read
		got, err := store.GetInspectionPolicyByID(ctx, LockingStrengthShare, accountID, "ip-1")
		require.NoError(t, err)
		assert.Equal(t, "Block gambling", got.Name)
		assert.Equal(t, "Block all gambling sites", got.Description)
		assert.True(t, got.Enabled)
		require.Len(t, got.Rules, 2)
		assert.Equal(t, []string{"*.gambling.com", "*.betting.com"}, got.Rules[0].Domains)
		assert.Equal(t, "block", got.Rules[0].Action)
		assert.Equal(t, []string{"https"}, got.Rules[0].Protocols)
		assert.Equal(t, []string{"10.0.0.0/8"}, got.Rules[1].Networks)

		// List
		policies, err := store.GetAccountInspectionPolicies(ctx, LockingStrengthShare, accountID)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, "ip-1", policies[0].ID)

		// Update
		policy.Name = "Block gambling updated"
		policy.Rules = append(policy.Rules, types.InspectionPolicyRule{
			Domains:  []string{"*.phishing.net"},
			Action:   "inspect",
			Priority: 3,
		})
		err = store.SaveInspectionPolicy(ctx, LockingStrengthUpdate, policy)
		require.NoError(t, err)

		got, err = store.GetInspectionPolicyByID(ctx, LockingStrengthShare, accountID, "ip-1")
		require.NoError(t, err)
		assert.Equal(t, "Block gambling updated", got.Name)
		require.Len(t, got.Rules, 3)
		assert.Equal(t, "inspect", got.Rules[2].Action)

		// Delete
		err = store.DeleteInspectionPolicy(ctx, LockingStrengthUpdate, accountID, "ip-1")
		require.NoError(t, err)

		_, err = store.GetInspectionPolicyByID(ctx, LockingStrengthShare, accountID, "ip-1")
		assert.Error(t, err)

		policies, err = store.GetAccountInspectionPolicies(ctx, LockingStrengthShare, accountID)
		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}

func TestSqlStore_InspectionPolicyNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "test-account-no-ip"

		account := newAccountWithId(ctx, accountID, "test-user", "example.com")
		err := store.SaveAccount(ctx, account)
		require.NoError(t, err)

		_, err = store.GetInspectionPolicyByID(ctx, LockingStrengthShare, accountID, "nonexistent")
		assert.Error(t, err)
	})
}

func TestSqlStore_InspectionPolicyIsolation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()

		// Create two accounts
		acc1 := newAccountWithId(ctx, "acc-1", "user-1", "one.com")
		acc2 := newAccountWithId(ctx, "acc-2", "user-2", "two.com")
		require.NoError(t, store.SaveAccount(ctx, acc1))
		require.NoError(t, store.SaveAccount(ctx, acc2))

		// Save policy for acc-1
		policy := &types.InspectionPolicy{
			ID:        "ip-acc1",
			AccountID: "acc-1",
			Name:      "Account 1 policy",
			Enabled:   true,
			Rules:     []types.InspectionPolicyRule{{Action: "block", Priority: 1}},
		}
		require.NoError(t, store.SaveInspectionPolicy(ctx, LockingStrengthUpdate, policy))

		// acc-2 should not see acc-1's policy
		policies, err := store.GetAccountInspectionPolicies(ctx, LockingStrengthShare, "acc-2")
		require.NoError(t, err)
		assert.Empty(t, policies)

		// acc-2 should not be able to get acc-1's policy by ID
		_, err = store.GetInspectionPolicyByID(ctx, LockingStrengthShare, "acc-2", "ip-acc1")
		assert.Error(t, err)
	})
}
