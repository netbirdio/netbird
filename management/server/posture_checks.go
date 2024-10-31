package server

import (
	"context"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

func (am *DefaultAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return nil, status.NewUnauthorizedToViewPostureChecksError()
	}

	return am.Store.GetPostureChecksByID(ctx, LockingStrengthShare, accountID, postureChecksID)
}

// SavePostureChecks saves a posture check.
func (am *DefaultAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, isUpdate bool) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return status.NewUnauthorizedToViewPostureChecksError()
	}

	if err = am.validatePostureChecks(ctx, accountID, postureChecks); err != nil {
		return status.Errorf(status.InvalidArgument, err.Error())
	}

	updateAccountPeers, err := am.arePostureCheckChangesAffectPeers(ctx, accountID, postureChecks.ID, isUpdate)
	if err != nil {
		return err
	}

	action := activity.PostureCheckCreated
	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if isUpdate {
			action = activity.PostureCheckUpdated

			if _, err := transaction.GetPostureChecksByID(ctx, LockingStrengthShare, accountID, postureChecks.ID); err != nil {
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

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
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

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return status.NewUnauthorizedToViewPostureChecksError()
	}

	postureChecks, err := am.Store.GetPostureChecksByID(ctx, LockingStrengthShare, accountID, postureChecksID)
	if err != nil {
		return err
	}

	if err = am.isPostureCheckLinkedToPolicy(ctx, postureChecksID, accountID); err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if err = transaction.DeletePostureChecks(ctx, LockingStrengthUpdate, accountID, postureChecksID); err != nil {
			return fmt.Errorf("failed to delete posture checks: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	return nil
}

// ListPostureChecks returns a list of posture checks.
func (am *DefaultAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return nil, status.NewUnauthorizedToViewPostureChecksError()
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
func (am *DefaultAccountManager) getPeerPostureChecks(ctx context.Context, accountID string, peerID string) ([]*posture.Checks, error) {
	postureChecks, err := am.Store.GetAccountPostureChecks(ctx, LockingStrengthShare, accountID)
	if err != nil || len(postureChecks) == 0 {
		return nil, err
	}

	policies, err := am.Store.GetAccountPolicies(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	peerPostureChecks := make(map[string]*posture.Checks)

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		isInGroup, err := am.isPeerInPolicySourceGroups(ctx, accountID, peerID, policy)
		if err != nil {
			return nil, err
		}

		if isInGroup {
			for _, sourcePostureCheckID := range policy.SourcePostureChecks {
				postureCheck, err := am.Store.GetPostureChecksByID(ctx, LockingStrengthShare, accountID, sourcePostureCheckID)
				if err == nil {
					peerPostureChecks[sourcePostureCheckID] = postureCheck
				}
			}
		}
	}

	return maps.Values(peerPostureChecks), nil
}

// isPeerInPolicySourceGroups checks if a peer is present in any of the policy rule source groups.
func (am *DefaultAccountManager) isPeerInPolicySourceGroups(ctx context.Context, accountID, peerID string, policy *Policy) (bool, error) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		for _, sourceGroup := range rule.Sources {
			group, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, sourceGroup)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to check peer in policy source group: %v", err)
				return false, fmt.Errorf("failed to check peer in policy source group: %w", err)
			}

			if slices.Contains(group.Peers, peerID) {
				return true, nil
			}
		}
	}

	return false, nil
}

// arePostureCheckChangesAffectPeers checks if the changes in posture checks are affecting peers.
func (am *DefaultAccountManager) arePostureCheckChangesAffectPeers(ctx context.Context, accountID, postureCheckID string, exists bool) (bool, error) {
	if !exists {
		return false, nil
	}

	policies, err := am.Store.GetAccountPolicies(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return false, err
	}

	for _, policy := range policies {
		if slices.Contains(policy.SourcePostureChecks, postureCheckID) {
			hasPeers, err := am.anyGroupHasPeers(ctx, accountID, policy.ruleGroups())
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
