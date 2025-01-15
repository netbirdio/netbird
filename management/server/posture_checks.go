package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/xid"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func (am *DefaultAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetPostureChecksByID(ctx, store.LockingStrengthShare, accountID, postureChecksID)
}

// SavePostureChecks saves a posture check.
func (am *DefaultAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks) (*posture.Checks, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return nil, status.NewAdminPermissionError()
	}

	var updateAccountPeers bool
	var isUpdate = postureChecks.ID != ""
	var action = activity.PostureCheckCreated

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validatePostureChecks(ctx, transaction, accountID, postureChecks); err != nil {
			return err
		}

		if isUpdate {
			updateAccountPeers, err = arePostureCheckChangesAffectPeers(ctx, transaction, accountID, postureChecks.ID)
			if err != nil {
				return err
			}

			if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
				return err
			}

			action = activity.PostureCheckUpdated
		}

		postureChecks.AccountID = accountID
		return transaction.SavePostureChecks(ctx, store.LockingStrengthUpdate, postureChecks)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, action, postureChecks.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return postureChecks, nil
}

// DeletePostureChecks deletes a posture check by ID.
func (am *DefaultAccountManager) DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return status.NewAdminPermissionError()
	}

	var postureChecks *posture.Checks

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		postureChecks, err = transaction.GetPostureChecksByID(ctx, store.LockingStrengthShare, accountID, postureChecksID)
		if err != nil {
			return err
		}

		if err = isPostureCheckLinkedToPolicy(ctx, transaction, postureChecksID, accountID); err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.DeletePostureChecks(ctx, store.LockingStrengthUpdate, accountID, postureChecksID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	return nil
}

// ListPostureChecks returns a list of posture checks.
func (am *DefaultAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountPostureChecks(ctx, store.LockingStrengthShare, accountID)
}

// getPeerPostureChecks returns the posture checks applied for a given peer.
func (am *DefaultAccountManager) getPeerPostureChecks(account *types.Account, peerID string) ([]*posture.Checks, error) {
	peerPostureChecks := make(map[string]*posture.Checks)

	if len(account.PostureChecks) == 0 {
		return nil, nil
	}

	for _, policy := range account.Policies {
		if !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}

		if err := addPolicyPostureChecks(account, peerID, policy, peerPostureChecks); err != nil {
			return nil, err
		}
	}

	return maps.Values(peerPostureChecks), nil
}

// arePostureCheckChangesAffectPeers checks if the changes in posture checks are affecting peers.
func arePostureCheckChangesAffectPeers(ctx context.Context, transaction store.Store, accountID, postureCheckID string) (bool, error) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return false, err
	}

	for _, policy := range policies {
		if slices.Contains(policy.SourcePostureChecks, postureCheckID) {
			hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, accountID, policy.RuleGroups())
			if err != nil {
				return false, err
			}

			if hasPeers {
				return true, nil
			}
		}
	}

	return false, nil
}

// validatePostureChecks validates the posture checks.
func validatePostureChecks(ctx context.Context, transaction store.Store, accountID string, postureChecks *posture.Checks) error {
	if err := postureChecks.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, err.Error()) //nolint
	}

	// If the posture check already has an ID, verify its existence in the store.
	if postureChecks.ID != "" {
		if _, err := transaction.GetPostureChecksByID(ctx, store.LockingStrengthShare, accountID, postureChecks.ID); err != nil {
			return err
		}
		return nil
	}

	// For new posture checks, ensure no duplicates by name.
	checks, err := transaction.GetAccountPostureChecks(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	for _, check := range checks {
		if check.Name == postureChecks.Name && check.ID != postureChecks.ID {
			return status.Errorf(status.InvalidArgument, "posture checks with name %s already exists", postureChecks.Name)
		}
	}

	postureChecks.ID = xid.New().String()

	return nil
}

// addPolicyPostureChecks adds posture checks from a policy to the peer posture checks map if the peer is in the policy's source groups.
func addPolicyPostureChecks(account *types.Account, peerID string, policy *types.Policy, peerPostureChecks map[string]*posture.Checks) error {
	isInGroup, err := isPeerInPolicySourceGroups(account, peerID, policy)
	if err != nil {
		return err
	}

	if !isInGroup {
		return nil
	}

	for _, sourcePostureCheckID := range policy.SourcePostureChecks {
		postureCheck := account.GetPostureChecks(sourcePostureCheckID)
		if postureCheck == nil {
			return errors.New("failed to add policy posture checks: posture checks not found")
		}
		peerPostureChecks[sourcePostureCheckID] = postureCheck
	}

	return nil
}

// isPeerInPolicySourceGroups checks if a peer is present in any of the policy rule source groups.
func isPeerInPolicySourceGroups(account *types.Account, peerID string, policy *types.Policy) (bool, error) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		for _, sourceGroup := range rule.Sources {
			group := account.GetGroup(sourceGroup)
			if group == nil {
				return false, fmt.Errorf("failed to check peer in policy source group: group not found")
			}

			if slices.Contains(group.Peers, peerID) {
				return true, nil
			}
		}
	}

	return false, nil
}

// isPostureCheckLinkedToPolicy checks whether the posture check is linked to any account policy.
func isPostureCheckLinkedToPolicy(ctx context.Context, transaction store.Store, postureChecksID, accountID string) error {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	for _, policy := range policies {
		if slices.Contains(policy.SourcePostureChecks, postureChecksID) {
			return status.Errorf(status.PreconditionFailed, "posture checks have been linked to policy: %s", policy.Name)
		}
	}

	return nil
}
