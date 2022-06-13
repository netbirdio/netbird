package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
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

// GetRule of ACL from the store
func (am *DefaultAccountManager) GetRule(accountID, ruleID string) (*Rule, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	rule, ok := account.Rules[ruleID]
	if ok {
		return rule, nil
	}

	return nil, status.Errorf(codes.NotFound, "rule with ID %s not found", ruleID)
}

// SaveRule of ACL in the store
func (am *DefaultAccountManager) SaveRule(accountID string, rule *Rule) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
	}

	account.Rules[rule.ID] = rule

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// UpdateRule updates a rule using a list of operations
func (am *DefaultAccountManager) UpdateRule(accountID string, ruleID string,
	operations []RuleUpdateOperation) (*Rule, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	ruleToUpdate, ok := account.Rules[ruleID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "rule %s no longer exists", ruleID)
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
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse flow")
			}
			rule.Flow = TrafficFlowBidirect
		case UpdateRuleStatus:
			if strings.ToLower(operation.Values[0]) == "true" {
				rule.Disabled = true
			} else if strings.ToLower(operation.Values[0]) == "false" {
				rule.Disabled = false
			} else {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse status")
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
		return nil, status.Errorf(codes.Internal, "failed to update account peers")
	}

	return rule, nil
}

// DeleteRule of ACL from the store
func (am *DefaultAccountManager) DeleteRule(accountID, ruleID string) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
	}

	delete(account.Rules, ruleID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// ListRules of ACL from the store
func (am *DefaultAccountManager) ListRules(accountID string) ([]*Rule, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	rules := make([]*Rule, 0, len(account.Rules))
	for _, item := range account.Rules {
		rules = append(rules, item)
	}

	return rules, nil
}
