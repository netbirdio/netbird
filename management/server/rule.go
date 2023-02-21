package server

import (
	"strings"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
)

// TrafficFlowType defines allowed direction of the traffic in the rule
type TrafficFlowType int

const (
	// TrafficFlowBidirect allows traffic to both direction
	TrafficFlowBidirect TrafficFlowType = iota
	// TrafficFlowBidirectString allows traffic to both direction
	TrafficFlowBidirectString = "bidirect"
	// DefaultRuleName is a name for the Default rule that is created for every account
	DefaultRuleName = "Default"
	// DefaultRuleDescription is a description for the Default rule that is created for every account
	DefaultRuleDescription = "This is a default rule that allows connections between all the resources"
	// DefaultPolicyName is a name for the Default policy that is created for every account
	DefaultPolicyName = "Default"
	// DefaultPolicyDescription is a description for the Default policy that is created for every account
	DefaultPolicyDescription = "This is a default policy that allows connections between all the resources"
)

// Rule of ACL for groups
type Rule struct {
	// ID of the rule
	ID string

	// Name of the rule visible in the UI
	Name string

	// Description of the rule visible in the UI
	Description string

	// Disabled status of rule in the system
	Disabled bool

	// Source list of groups IDs of peers
	Source []string

	// Destination list of groups IDs of peers
	Destination []string

	// Flow of the traffic allowed by the rule
	Flow TrafficFlowType
}

const (
	// UpdateRuleName indicates a rule name update operation
	UpdateRuleName RuleUpdateOperationType = iota
	// UpdateRuleDescription indicates a rule description update operation
	UpdateRuleDescription
	// UpdateRuleStatus indicates a rule status update operation
	UpdateRuleStatus
	// UpdateRuleFlow indicates a rule flow update operation
	UpdateRuleFlow
	// InsertGroupsToSource indicates an insert groups to source rule operation
	InsertGroupsToSource
	// RemoveGroupsFromSource indicates an remove groups from source rule operation
	RemoveGroupsFromSource
	// UpdateSourceGroups indicates a replacement of source group list of a rule operation
	UpdateSourceGroups
	// InsertGroupsToDestination indicates an insert groups to destination rule operation
	InsertGroupsToDestination
	// RemoveGroupsFromDestination indicates an remove groups from destination rule operation
	RemoveGroupsFromDestination
	// UpdateDestinationGroups indicates a replacement of destination group list of a rule operation
	UpdateDestinationGroups
)

// RuleUpdateOperationType operation type
type RuleUpdateOperationType int

// RuleUpdateOperation operation object with type and values to be applied
type RuleUpdateOperation struct {
	Type   RuleUpdateOperationType
	Values []string
}

func (r *Rule) Copy() *Rule {
	return &Rule{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Disabled:    r.Disabled,
		Source:      r.Source[:],
		Destination: r.Destination[:],
		Flow:        r.Flow,
	}
}

// EventMeta returns activity event meta related to this rule
func (r *Rule) EventMeta() map[string]any {
	return map[string]any{"name": r.Name}
}

// GetRule of ACL from the store
func (am *DefaultAccountManager) GetRule(accountID, ruleID, userID string) (*Rule, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "only admins are allowed to view rules")
	}

	rule, ok := account.Rules[ruleID]
	if ok {
		return rule, nil
	}

	return nil, status.Errorf(status.NotFound, "rule with ID %s not found", ruleID)
}

// SaveRule of ACL in the store
func (am *DefaultAccountManager) SaveRule(accountID, userID string, rule *Rule) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	_, exists := account.Rules[rule.ID]

	account.Rules[rule.ID] = rule

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	action := activity.RuleAdded
	if exists {
		action = activity.RuleUpdated
	}
	am.storeEvent(userID, rule.ID, accountID, action, rule.EventMeta())

	return am.updateAccountPeers(account)
}

// UpdateRule updates a rule using a list of operations
func (am *DefaultAccountManager) UpdateRule(accountID string, ruleID string,
	operations []RuleUpdateOperation,
) (*Rule, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	ruleToUpdate, ok := account.Rules[ruleID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "rule %s no longer exists", ruleID)
	}

	rule := ruleToUpdate.Copy()

	for _, operation := range operations {
		switch operation.Type {
		case UpdateRuleName:
			rule.Name = operation.Values[0]
		case UpdateRuleDescription:
			rule.Description = operation.Values[0]
		case UpdateRuleFlow:
			if operation.Values[0] != TrafficFlowBidirectString {
				return nil, status.Errorf(status.InvalidArgument, "failed to parse flow")
			}
			rule.Flow = TrafficFlowBidirect
		case UpdateRuleStatus:
			if strings.ToLower(operation.Values[0]) == "true" {
				rule.Disabled = true
			} else if strings.ToLower(operation.Values[0]) == "false" {
				rule.Disabled = false
			} else {
				return nil, status.Errorf(status.InvalidArgument, "failed to parse status")
			}
		case UpdateSourceGroups:
			rule.Source = operation.Values
		case InsertGroupsToSource:
			sourceList := rule.Source
			resultList := removeFromList(sourceList, operation.Values)
			rule.Source = append(resultList, operation.Values...)
		case RemoveGroupsFromSource:
			sourceList := rule.Source
			resultList := removeFromList(sourceList, operation.Values)
			rule.Source = resultList
		case UpdateDestinationGroups:
			rule.Destination = operation.Values
		case InsertGroupsToDestination:
			sourceList := rule.Destination
			resultList := removeFromList(sourceList, operation.Values)
			rule.Destination = append(resultList, operation.Values...)
		case RemoveGroupsFromDestination:
			sourceList := rule.Destination
			resultList := removeFromList(sourceList, operation.Values)
			rule.Destination = resultList
		}
	}

	account.Rules[ruleID] = rule

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to update account peers")
	}

	return rule, nil
}

// DeleteRule of ACL from the store
func (am *DefaultAccountManager) DeleteRule(accountID, ruleID, userID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	rule := account.Rules[ruleID]
	if rule == nil {
		return status.Errorf(status.NotFound, "rule with ID %s doesn't exist", ruleID)
	}
	delete(account.Rules, ruleID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.storeEvent(userID, rule.ID, accountID, activity.RuleRemoved, rule.EventMeta())

	return am.updateAccountPeers(account)
}

// ListRules of ACL from the store
func (am *DefaultAccountManager) ListRules(accountID, userID string) ([]*Rule, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "Only Administrators can view Access Rules")
	}

	rules := make([]*Rule, 0, len(account.Rules))
	for _, item := range account.Rules {
		rules = append(rules, item)
	}

	return rules, nil
}
