package server

import (
	"context"
	_ "embed"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetPolicy from the store
func (am *DefaultAccountManager) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetPolicyByID(ctx, store.LockingStrengthNone, accountID, policyID)
}

// SavePolicy in the store
func (am *DefaultAccountManager) SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error) {
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

	var isUpdate = policy.ID != ""
	var existingPolicy *types.Policy
	var action = activity.PolicyAdded
	var unchanged bool
	var affectedPeerIDs []string

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existingPolicy, err = validatePolicy(ctx, transaction, accountID, policy)
		if err != nil {
			return err
		}

		if isUpdate {
			if policy.Equal(existingPolicy) {
				log.WithContext(ctx).Tracef("policy update skipped because equal to stored one - policy id %s", policy.ID)
				unchanged = true
				return nil
			}

			action = activity.PolicyUpdated

			policy.AccountSeqID = existingPolicy.AccountSeqID

			if err = transaction.SavePolicy(ctx, policy); err != nil {
				return err
			}
		} else {
			seq, err := transaction.AllocateAccountSeqID(ctx, accountID, types.AccountSeqEntityPolicy)
			if err != nil {
				return err
			}
			policy.AccountSeqID = seq

			if err = transaction.CreatePolicy(ctx, policy); err != nil {
				return err
			}
		}

		groupIDs, directPeerIDs := collectPolicyAffectedGroupsAndPeers(ctx, policy, existingPolicy)
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, groupIDs, directPeerIDs)

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return nil, err
	}

	if unchanged {
		return policy, nil
	}

	am.StoreEvent(ctx, userID, policy.ID, accountID, action, policy.EventMeta())

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Tracef("SavePolicy %s: updating %d affected peers: %v", policy.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("SavePolicy %s: no affected peers", policy.ID)
	}

	return policy, nil
}

// DeletePolicy from the store
func (am *DefaultAccountManager) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var policy *types.Policy
	var affectedPeerIDs []string

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		policy, err = transaction.GetPolicyByID(ctx, store.LockingStrengthUpdate, accountID, policyID)
		if err != nil {
			return err
		}

		groupIDs, directPeerIDs := collectPolicyAffectedGroupsAndPeers(ctx, policy)
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, groupIDs, directPeerIDs)

		if err = transaction.DeletePolicy(ctx, accountID, policyID); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, policyID, accountID, activity.PolicyRemoved, policy.EventMeta())

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("DeletePolicy %s: updating %d affected peers: %v", policyID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("DeletePolicy %s: no affected peers", policyID)
	}

	return nil
}

// ListPolicies from the store.
func (am *DefaultAccountManager) ListPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Policies, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
}

// collectPolicyAffectedGroupsAndPeers returns group IDs and direct peer IDs from the given policies.
func collectPolicyAffectedGroupsAndPeers(ctx context.Context, policies ...*types.Policy) (groupIDs []string, directPeerIDs []string) {
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		ruleGroups := policy.RuleGroups()
		log.WithContext(ctx).Tracef("collectPolicyAffectedGroupsAndPeers: policy %s (%s) ruleGroups=%v", policy.ID, policy.Name, ruleGroups)
		groupIDs = append(groupIDs, ruleGroups...)
		for _, rule := range policy.Rules {
			if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
				log.WithContext(ctx).Tracef("collectPolicyAffectedGroupsAndPeers: policy %s rule %s direct source peer %s", policy.ID, rule.ID, rule.SourceResource.ID)
				directPeerIDs = append(directPeerIDs, rule.SourceResource.ID)
			}
			if rule.DestinationResource.Type == types.ResourceTypePeer && rule.DestinationResource.ID != "" {
				log.WithContext(ctx).Tracef("collectPolicyAffectedGroupsAndPeers: policy %s rule %s direct destination peer %s", policy.ID, rule.ID, rule.DestinationResource.ID)
				directPeerIDs = append(directPeerIDs, rule.DestinationResource.ID)
			}
		}
	}
	log.WithContext(ctx).Tracef("collectPolicyAffectedGroupsAndPeers: result groupIDs=%v, directPeerIDs=%v", groupIDs, directPeerIDs)
	return
}

// validatePolicy validates the policy and its rules. For updates it returns
// the existing policy loaded from the store so callers can avoid a second read.
func validatePolicy(ctx context.Context, transaction store.Store, accountID string, policy *types.Policy) (*types.Policy, error) {
	var existingPolicy *types.Policy
	if policy.ID != "" {
		var err error
		existingPolicy, err = transaction.GetPolicyByID(ctx, store.LockingStrengthNone, accountID, policy.ID)
		if err != nil {
			return nil, err
		}

		// TODO: Refactor to support multiple rules per policy
		existingRuleIDs := make(map[string]bool)
		for _, rule := range existingPolicy.Rules {
			existingRuleIDs[rule.ID] = true
		}

		for _, rule := range policy.Rules {
			if rule.ID != "" && !existingRuleIDs[rule.ID] {
				return nil, status.Errorf(status.InvalidArgument, "invalid rule ID: %s", rule.ID)
			}
		}
	} else {
		policy.ID = xid.New().String()
		policy.AccountID = accountID
	}

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, policy.RuleGroups())
	if err != nil {
		return nil, err
	}

	postureChecks, err := transaction.GetPostureChecksByIDs(ctx, store.LockingStrengthNone, accountID, policy.SourcePostureChecks)
	if err != nil {
		return nil, err
	}

	for i, rule := range policy.Rules {
		ruleCopy := rule.Copy()
		if ruleCopy.ID == "" {
			ruleCopy.ID = policy.ID // TODO: when policy can contain multiple rules, need refactor
			ruleCopy.PolicyID = policy.ID
		}

		ruleCopy.Sources = getValidGroupIDs(groups, ruleCopy.Sources)
		ruleCopy.Destinations = getValidGroupIDs(groups, ruleCopy.Destinations)
		policy.Rules[i] = ruleCopy
	}

	if policy.SourcePostureChecks != nil {
		policy.SourcePostureChecks = getValidPostureCheckIDs(postureChecks, policy.SourcePostureChecks)
	}

	return existingPolicy, nil
}

// getValidPostureCheckIDs filters and returns only the valid posture check IDs from the provided list.
func getValidPostureCheckIDs(postureChecks map[string]*posture.Checks, postureChecksIds []string) []string {
	validIDs := make([]string, 0, len(postureChecksIds))
	for _, id := range postureChecksIds {
		if _, exists := postureChecks[id]; exists {
			validIDs = append(validIDs, id)
		}
	}

	return validIDs
}

// getValidGroupIDs filters and returns only the valid group IDs from the provided list.
func getValidGroupIDs(groups map[string]*types.Group, groupIDs []string) []string {
	validIDs := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		if _, exists := groups[id]; exists {
			validIDs = append(validIDs, id)
		}
	}

	return validIDs
}
