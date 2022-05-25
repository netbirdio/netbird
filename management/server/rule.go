package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TrafficFlowType defines allowed direction of the traffic in the rule
type TrafficFlowType int

const (
	// TrafficFlowBidirect allows traffic to both direction
	TrafficFlowBidirect TrafficFlowType = iota
)

// Rule of ACL for groups
type Rule struct {
	// ID of the rule
	ID string

	// Name of the rule visible in the UI
	Name string

	// Source list of groups IDs of peers
	Source []string

	// Destination list of groups IDs of peers
	Destination []string

	// Flow of the traffic allowed by the rule
	Flow TrafficFlowType
}

func (r *Rule) Copy() *Rule {
	return &Rule{
		ID:          r.ID,
		Name:        r.Name,
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
