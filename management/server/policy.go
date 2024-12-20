package server

import (
	"context"
	_ "embed"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

// GetPolicy from the store
func (am *DefaultAccountManager) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetPolicyByID(ctx, store.LockingStrengthShare, accountID, policyID)
}

// SavePolicy in the store
func (am *DefaultAccountManager) SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy) (*types.Policy, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	var isUpdate = policy.ID != ""
	var updateAccountPeers bool
	var action = activity.PolicyAdded

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validatePolicy(ctx, transaction, accountID, policy); err != nil {
			return err
		}

		updateAccountPeers, err = arePolicyChangesAffectPeers(ctx, transaction, accountID, policy, isUpdate)
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		saveFunc := transaction.CreatePolicy
		if isUpdate {
			action = activity.PolicyUpdated
			saveFunc = transaction.SavePolicy
		}

		return saveFunc(ctx, store.LockingStrengthUpdate, policy)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, policy.ID, accountID, action, policy.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return policy, nil
}

// DeletePolicy from the store
func (am *DefaultAccountManager) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	var policy *types.Policy
	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		policy, err = transaction.GetPolicyByID(ctx, store.LockingStrengthUpdate, accountID, policyID)
		if err != nil {
			return err
		}

		updateAccountPeers, err = arePolicyChangesAffectPeers(ctx, transaction, accountID, policy, false)
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.DeletePolicy(ctx, store.LockingStrengthUpdate, accountID, policyID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, policyID, accountID, activity.PolicyRemoved, policy.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// ListPolicies from the store.
func (am *DefaultAccountManager) ListPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountPolicies(ctx, store.LockingStrengthShare, accountID)
}

// arePolicyChangesAffectPeers checks if changes to a policy will affect any associated peers.
func arePolicyChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, policy *types.Policy, isUpdate bool) (bool, error) {
	if isUpdate {
		existingPolicy, err := transaction.GetPolicyByID(ctx, store.LockingStrengthShare, accountID, policy.ID)
		if err != nil {
			return false, err
		}

		if !policy.Enabled && !existingPolicy.Enabled {
			return false, nil
		}

		hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, policy.AccountID, existingPolicy.RuleGroups())
		if err != nil {
			return false, err
		}

		if hasPeers {
			return true, nil
		}
	}

	return anyGroupHasPeersOrResources(ctx, transaction, policy.AccountID, policy.RuleGroups())
}

// validatePolicy validates the policy and its rules.
func validatePolicy(ctx context.Context, transaction store.Store, accountID string, policy *types.Policy) error {
	if policy.ID != "" {
		_, err := transaction.GetPolicyByID(ctx, store.LockingStrengthShare, accountID, policy.ID)
		if err != nil {
			return err
		}
	} else {
		policy.ID = xid.New().String()
		policy.AccountID = accountID
	}

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, policy.RuleGroups())
	if err != nil {
		return err
	}

	postureChecks, err := transaction.GetPostureChecksByIDs(ctx, store.LockingStrengthShare, accountID, policy.SourcePostureChecks)
	if err != nil {
		return err
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

	return nil
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

// toProtocolFirewallRules converts the firewall rules to the protocol firewall rules.
func toProtocolFirewallRules(rules []*types.FirewallRule) []*proto.FirewallRule {
	result := make([]*proto.FirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]

		result[i] = &proto.FirewallRule{
			PeerIP:    rule.PeerIP,
			Direction: getProtoDirection(rule.Direction),
			Action:    getProtoAction(rule.Action),
			Protocol:  getProtoProtocol(rule.Protocol),
			Port:      rule.Port,
		}
	}
	return result
}
