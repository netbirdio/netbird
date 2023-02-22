package server

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
)

const (
	// UpdatePolicyName indicates a policy name update operation
	UpdatePolicyName PolicyUpdateOperationType = iota
	// UpdatePolicyDescription indicates a policy description update operation
	UpdatePolicyDescription
	// UpdatePolicyStatus indicates a policy status update operation
	UpdatePolicyStatus
	// UpdatePolicyQuery indicates a policy query update operation
	UpdatePolicyQuery
)

// PolicyUpdateOperationType operation type
type PolicyUpdateOperationType int

// PolicyUpdateOperation operation object with type and values to be applied
type PolicyUpdateOperation struct {
	Type   PolicyUpdateOperationType
	Values []string
}

//go:embed rego/default_policy_module.rego
var defaultPolicyModule string

//go:embed rego/default_policy.rego
var defaultPolicy string

// Policy of the Rego query
type Policy struct {
	// ID of the policy
	ID string

	// Name of the Policy
	Name string

	// Description of the policy visible in the UI
	Description string

	// Disabled status of the policy
	Disabled bool

	// Query of Rego the policy
	Query string
}

// Copy returns a copy of the policy.
func (r *Policy) Copy() *Policy {
	return &Policy{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Disabled:    r.Disabled,
		Query:       r.Query,
	}
}

// EventMeta returns activity event meta related to this policy
func (p *Policy) EventMeta() map[string]any {
	return map[string]any{"name": p.Name}
}

// FirewallRule is a rule of the firewall.
type FirewallRule struct {
	// PeerID of the peer
	PeerID string

	// PeerIP of the peer
	PeerIP string

	// Direction of the traffic
	Direction string

	// Action of the traffic
	Action string

	// Port of the traffic
	Port string
}

// parseFromRegoResult parses the Rego result to a FirewallRule.
func (f *FirewallRule) parseFromRegoResult(value interface{}) error {
	object, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid Rego query eval result")
	}

	peerID, ok := object["ID"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer ID type")
	}

	peerIP, ok := object["IP"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer IP type")
	}

	direction, ok := object["Direction"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer direction type")
	}

	action, ok := object["Action"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer action type")
	}

	port, ok := object["Port"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer port type")
	}

	f.PeerID = peerID
	f.PeerIP = peerIP
	f.Direction = direction
	f.Action = action
	f.Port = port

	return nil
}

// getRegoQuery returns a initialized Rego object with default rule.
func (a *Account) getRegoQuery(policies ...*Policy) (rego.PreparedEvalQuery, error) {
	queries := []func(*rego.Rego){
		rego.Query("data.netbird.all"),
		rego.Module("netbird", defaultPolicyModule),
	}
	for i, p := range policies {
		queries = append(queries, rego.Module(fmt.Sprintf("netbird-%d", i), p.Query))
	}
	return rego.New(queries...).PrepareForEval(context.TODO())
}

// getPeersByPolicy returns all peers that given peer has access to.
func (a *Account) getPeersByPolicy(peerID string) ([]*Peer, []*FirewallRule) {
	input := map[string]interface{}{
		"peer_id": peerID,
		"peers":   a.Peers,
		"groups":  a.Groups,
	}

	query, err := a.getRegoQuery(a.Policies...)
	if err != nil {
		log.WithError(err).Error("get Rego query")
		return nil, nil
	}

	evalResult, err := query.Eval(
		context.TODO(),
		rego.EvalInput(input),
	)
	if err != nil {
		log.WithError(err).Error("eval Rego query")
		return nil, nil
	}

	if len(evalResult) == 0 || len(evalResult[0].Expressions) == 0 {
		log.Error("empty Rego query eval result")
		return nil, nil
	}
	expression, ok := evalResult[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, nil
	}

	set := make(map[string]struct{})
	peers := make([]*Peer, 0, len(expression))
	rules := make([]*FirewallRule, 0, len(expression))
	for _, v := range expression {
		rule := &FirewallRule{}
		if err := rule.parseFromRegoResult(v); err != nil {
			log.WithError(err).Error("parse Rego query eval result")
			continue
		}
		rules = append(rules, rule)
		if _, ok := set[rule.PeerID]; ok {
			continue
		}
		peers = append(peers, a.Peers[rule.PeerID])
		set[rule.PeerID] = struct{}{}
	}

	return peers, rules
}

// GetPolicy from the store
func (am *DefaultAccountManager) GetPolicy(accountID, policyID, userID string) (*Policy, error) {
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
		return nil, status.Errorf(status.PermissionDenied, "only admins are allowed to view policies")
	}

	for _, policy := range account.Policies {
		if policy.ID == policyID {
			return policy, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "policy with ID %s not found", policyID)
}

// SaveRule in the store
func (am *DefaultAccountManager) SavePolicy(accountID, userID string, policy *Policy) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	exists := false
	for i, p := range account.Policies {
		if p.ID == policy.ID {
			account.Policies[i] = policy
			exists = true
			break
		}
	}
	if !exists {
		account.Policies = append(account.Policies, policy)
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	action := activity.PolicyAdded
	if exists {
		action = activity.PolicyUpdated
	}
	am.storeEvent(userID, policy.ID, accountID, action, policy.EventMeta())

	return am.updateAccountPeers(account)
}

// UpdatePolicy updates a rule using a list of operations
func (am *DefaultAccountManager) UpdatePolicy(accountID string, ruleID string,
	operations []PolicyUpdateOperation,
) (*Policy, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	policyIdx := -1
	for i, policy := range account.Policies {
		if policy.ID == ruleID {
			policyIdx = i
			break
		}
	}
	if policyIdx >= 0 {
		return nil, status.Errorf(status.NotFound, "policy %s no longer exists", ruleID)
	}
	policyToUpdate := account.Policies[policyIdx]

	policy := policyToUpdate.Copy()

	for _, operation := range operations {
		switch operation.Type {
		case UpdatePolicyName:
			policy.Name = operation.Values[0]
		case UpdatePolicyDescription:
			policy.Description = operation.Values[0]
		case UpdatePolicyQuery:
			policy.Query = operation.Values[0]
		case UpdatePolicyStatus:
			if strings.ToLower(operation.Values[0]) == "true" {
				policy.Disabled = true
			} else if strings.ToLower(operation.Values[0]) == "false" {
				policy.Disabled = false
			} else {
				return nil, status.Errorf(status.InvalidArgument, "failed to parse status")
			}
		}
	}

	account.Policies[policyIdx] = policy

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to update account peers")
	}

	return policy, nil
}

// DeletePolicy from the store
func (am *DefaultAccountManager) DeletePolicy(accountID, policyID, userID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	policyIdx := -1
	for i, policy := range account.Policies {
		if policy.ID == policyID {
			policyIdx = i
			break
		}
	}
	if policyIdx < 0 {
		return status.Errorf(status.NotFound, "rule with ID %s doesn't exist", policyID)
	}

	policy := account.Policies[policyIdx]
	account.Policies = append(account.Policies[:policyIdx], account.Policies[policyIdx+1:]...)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.storeEvent(userID, policy.ID, accountID, activity.PolicyRemoved, policy.EventMeta())

	return am.updateAccountPeers(account)
}

// ListRules from the store
func (am *DefaultAccountManager) ListPolicies(accountID, userID string) ([]*Policy, error) {
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
		return nil, status.Errorf(status.PermissionDenied, "Only Administrators can view policies")
	}

	return account.Policies[:], nil
}
