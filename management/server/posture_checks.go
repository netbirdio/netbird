package server

import (
	"context"
	"slices"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (am *DefaultAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetPostureChecksByID(ctx, store.LockingStrengthNone, accountID, postureChecksID)
}

// SavePostureChecks saves a posture check.
func (am *DefaultAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, create bool) (*posture.Checks, error) {
	operation := operations.Create
	if !create {
		operation = operations.Update
	}
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operation)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	var isUpdate = postureChecks.ID != ""
	var action = activity.PostureCheckCreated
	var affectedPeerIDs []string

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validatePostureChecks(ctx, transaction, accountID, postureChecks); err != nil {
			return err
		}

		if isUpdate {
			action = activity.PostureCheckUpdated

			groupIDs, directPeerIDs := collectPostureCheckAffectedGroupsAndPeers(ctx, transaction, accountID, postureChecks.ID)
			affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, groupIDs, directPeerIDs)
		}

		postureChecks.AccountID = accountID
		if err = transaction.SavePostureChecks(ctx, postureChecks); err != nil {
			return err
		}

		if isUpdate {
			return transaction.IncrementNetworkSerial(ctx, accountID)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, action, postureChecks.EventMeta())

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("SavePostureChecks %s: updating %d affected peers: %v", postureChecks.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("SavePostureChecks %s: no affected peers", postureChecks.ID)
	}

	return postureChecks, nil
}

// DeletePostureChecks deletes a posture check by ID.
func (am *DefaultAccountManager) DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var postureChecks *posture.Checks

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		postureChecks, err = transaction.GetPostureChecksByID(ctx, store.LockingStrengthNone, accountID, postureChecksID)
		if err != nil {
			return err
		}

		if err = isPostureCheckLinkedToPolicy(ctx, transaction, postureChecksID, accountID); err != nil {
			return err
		}

		if err = transaction.DeletePostureChecks(ctx, accountID, postureChecksID); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	return nil
}

// ListPostureChecks returns a list of posture checks.
func (am *DefaultAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountPostureChecks(ctx, store.LockingStrengthNone, accountID)
}

// collectPostureCheckAffectedGroupsAndPeers returns group IDs and peer IDs from policies referencing the posture check.
func collectPostureCheckAffectedGroupsAndPeers(ctx context.Context, transaction store.Store, accountID, postureCheckID string) (groupIDs []string, directPeerIDs []string) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get policies for posture check affected peers resolution: %v", err)
		return nil, nil
	}

	for _, policy := range policies {
		if slices.Contains(policy.SourcePostureChecks, postureCheckID) {
			log.WithContext(ctx).Tracef("collectPostureCheckAffectedGroupsAndPeers: posture check %s referenced by policy %s (%s)", postureCheckID, policy.ID, policy.Name)
			gIDs, pIDs := collectPolicyAffectedGroupsAndPeers(ctx, policy)
			groupIDs = append(groupIDs, gIDs...)
			directPeerIDs = append(directPeerIDs, pIDs...)
		}
	}

	log.WithContext(ctx).Tracef("collectPostureCheckAffectedGroupsAndPeers: postureCheck=%s -> groupIDs=%v, directPeerIDs=%v", postureCheckID, groupIDs, directPeerIDs)
	return groupIDs, directPeerIDs
}

// validatePostureChecks validates the posture checks.
func validatePostureChecks(ctx context.Context, transaction store.Store, accountID string, postureChecks *posture.Checks) error {
	if err := postureChecks.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, "%v", err.Error()) //nolint
	}

	// If the posture check already has an ID, verify its existence in the store.
	if postureChecks.ID != "" {
		if _, err := transaction.GetPostureChecksByID(ctx, store.LockingStrengthNone, accountID, postureChecks.ID); err != nil {
			return err
		}
		return nil
	}

	// For new posture checks, ensure no duplicates by name.
	checks, err := transaction.GetAccountPostureChecks(ctx, store.LockingStrengthNone, accountID)
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

// isPostureCheckLinkedToPolicy checks whether the posture check is linked to any account policy.
func isPostureCheckLinkedToPolicy(ctx context.Context, transaction store.Store, postureChecksID, accountID string) error {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
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
