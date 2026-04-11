package server

import (
	"context"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// GetInspectionPolicy returns an inspection policy by ID.
func (am *DefaultAccountManager) GetInspectionPolicy(ctx context.Context, accountID, policyID, userID string) (*types.InspectionPolicy, error) {
	return am.Store.GetInspectionPolicyByID(ctx, store.LockingStrengthShare, accountID, policyID)
}

// SaveInspectionPolicy creates or updates an inspection policy.
func (am *DefaultAccountManager) SaveInspectionPolicy(ctx context.Context, accountID, userID string, policy *types.InspectionPolicy, create bool) (*types.InspectionPolicy, error) {
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if create {
			policy.ID = xid.New().String()
		}
		policy.AccountID = accountID
		return transaction.SaveInspectionPolicy(ctx, store.LockingStrengthUpdate, policy)
	})
	if err != nil {
		return nil, err
	}

	am.UpdateAccountPeers(ctx, accountID)

	return policy, nil
}

// DeleteInspectionPolicy removes an inspection policy.
func (am *DefaultAccountManager) DeleteInspectionPolicy(ctx context.Context, accountID, policyID, userID string) error {
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		return transaction.DeleteInspectionPolicy(ctx, store.LockingStrengthUpdate, accountID, policyID)
	})
	if err != nil {
		return err
	}

	am.UpdateAccountPeers(ctx, accountID)

	return nil
}

// ListInspectionPolicies returns all inspection policies for the account.
func (am *DefaultAccountManager) ListInspectionPolicies(ctx context.Context, accountID, userID string) ([]*types.InspectionPolicy, error) {
	return am.Store.GetAccountInspectionPolicies(ctx, store.LockingStrengthShare, accountID)
}
