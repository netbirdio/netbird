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

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name of the rule visible in the UI
	Name string

	// Description of the rule visible in the UI
	Description string

	// Disabled status of rule in the system
	Disabled bool

	// Source list of groups IDs of peers
	Source []string `gorm:"serializer:json"`

	// Destination list of groups IDs of peers
	Destination []string `gorm:"serializer:json"`

	// Flow of the traffic allowed by the rule
	Flow TrafficFlowType
}

func (r *Rule) Copy() *Rule {
	rule := &Rule{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Disabled:    r.Disabled,
		Source:      make([]string, len(r.Source)),
		Destination: make([]string, len(r.Destination)),
		Flow:        r.Flow,
	}
	copy(rule.Source, r.Source)
	copy(rule.Destination, r.Destination)
	return rule
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
	return &Policy{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     !rule.Disabled,
		Rules:       []*PolicyRule{rule.ToPolicyRule()},
	}, nil
}
