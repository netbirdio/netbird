package server

import (
	"context"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

const (
	errMsgPostureAdminOnly = "only users with admin power are allowed to view posture checks"
)

func (am *DefaultAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() || user.AccountID != accountID {
		return nil, status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	return am.Store.GetPostureChecksByID(ctx, LockingStrengthShare, postureChecksID, accountID)
}

// SavePostureChecks saves a posture check.
func (am *DefaultAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, isUpdate bool) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() || user.AccountID != accountID {
		return status.Errorf(status.PermissionDenied, "only admin users are allowed to update posture checks")
	}

	if err = am.validatePostureChecks(ctx, accountID, postureChecks); err != nil {
		return status.Errorf(status.InvalidArgument, err.Error())
	}

	action := activity.PostureCheckCreated

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if isUpdate {
			action = activity.PostureCheckUpdated

			if _, err := transaction.GetPostureChecksByID(ctx, LockingStrengthShare, postureChecks.ID, accountID); err != nil {
				return fmt.Errorf("failed to get posture checks: %w", err)
			}

			if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
				return fmt.Errorf("failed to increment network serial: %w", err)
			}
		}

		if err = transaction.SavePostureChecks(ctx, LockingStrengthUpdate, postureChecks); err != nil {
			return fmt.Errorf("failed to save posture checks: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, action, postureChecks.EventMeta())

	if isUpdate {
		account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
		if err != nil {
			return fmt.Errorf("error getting account: %w", err)
		}
		am.updateAccountPeers(ctx, account)
	}

	return nil
}

func (am *DefaultAccountManager) validatePostureChecks(ctx context.Context, accountID string, postureChecks *posture.Checks) error {
	if err := postureChecks.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, err.Error()) //nolint
	}

	checks, err := am.Store.GetAccountPostureChecks(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	for _, check := range checks {
		if check.Name == postureChecks.Name && check.ID != postureChecks.ID {
			return status.Errorf(status.InvalidArgument, "posture checks with name %s already exists", postureChecks.Name)
		}
	}

	return nil
}

// DeletePostureChecks deletes a posture check by ID.
func (am *DefaultAccountManager) DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() || user.AccountID != accountID {
		return status.Errorf(status.PermissionDenied, "only admin users are allowed to delete posture checks")
	}

	if err = am.isPostureCheckLinkedToPolicy(ctx, postureChecksID, accountID); err != nil {
		return err
	}

	postureChecks, err := am.Store.GetPostureChecksByID(ctx, LockingStrengthShare, postureChecksID, accountID)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if err = transaction.DeletePostureChecks(ctx, LockingStrengthUpdate, postureChecksID, accountID); err != nil {
			return fmt.Errorf("failed to delete posture checks: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return fmt.Errorf("error getting account: %w", err)
	}
	am.updateAccountPeers(ctx, account)

	return nil
}

// ListPostureChecks returns a list of posture checks.
func (am *DefaultAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() || user.AccountID != accountID {
		return nil, status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	return am.Store.GetAccountPostureChecks(ctx, LockingStrengthShare, accountID)
}

// isPostureCheckLinkedToPolicy checks whether the posture check is linked to any account policy.
func (am *DefaultAccountManager) isPostureCheckLinkedToPolicy(ctx context.Context, postureChecksID, accountID string) error {
	policies, err := am.Store.GetAccountPolicies(ctx, LockingStrengthShare, accountID)
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

// getPeerPostureChecks returns the posture checks applied for a given peer.
func (am *DefaultAccountManager) getPeerPostureChecks(account *Account, peer *nbpeer.Peer) []*posture.Checks {
	peerPostureChecks := make(map[string]posture.Checks)

	if len(account.PostureChecks) == 0 {
		return nil
	}

	for _, policy := range account.Policies {
		if !policy.Enabled {
			continue
		}

		if isPeerInPolicySourceGroups(peer.ID, account, policy) {
			addPolicyPostureChecks(account, policy, peerPostureChecks)
		}
	}

	postureChecksList := make([]*posture.Checks, 0, len(peerPostureChecks))
	for _, check := range peerPostureChecks {
		checkCopy := check
		postureChecksList = append(postureChecksList, &checkCopy)
	}

	return postureChecksList
}

// isPeerInPolicySourceGroups checks if a peer is present in any of the policy rule source groups.
func isPeerInPolicySourceGroups(peerID string, account *Account, policy *Policy) bool {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		for _, sourceGroup := range rule.Sources {
			group, ok := account.Groups[sourceGroup]
			if ok && slices.Contains(group.Peers, peerID) {
				return true
			}
		}
	}

	return false
}

func addPolicyPostureChecks(account *Account, policy *Policy, peerPostureChecks map[string]posture.Checks) {
	for _, sourcePostureCheckID := range policy.SourcePostureChecks {
		for _, postureCheck := range account.PostureChecks {
			if postureCheck.ID == sourcePostureCheckID {
				peerPostureChecks[sourcePostureCheckID] = *postureCheck
			}
		}
	}
}
