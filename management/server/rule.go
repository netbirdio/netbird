package server

import "fmt"

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

// ToPolicyRule converts a Rule to a PolicyRule object
func (r *Rule) ToPolicyRule() *PolicyRule {
	if r == nil {
		return nil
	}
	return &PolicyRule{
		ID:            r.ID,
		Name:          r.Name,
		Enabled:       !r.Disabled,
		Description:   r.Description,
		Destinations:  r.Destination,
		Sources:       r.Source,
		Bidirectional: true,
		Protocol:      PolicyRuleProtocolALL,
		Action:        PolicyTrafficActionAccept,
	}
}

// RuleToPolicy converts a Rule to a Policy query object
func RuleToPolicy(rule *Rule) (*Policy, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is empty")
	}
	policy := &Policy{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     !rule.Disabled,
		Rules:       []*PolicyRule{rule.ToPolicyRule()},
	}
	if err := policy.UpdateQueryFromRules(); err != nil {
		return nil, err
	}
	return policy, nil
}
