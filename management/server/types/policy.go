package types

const (
	// PolicyRuleFlowDirect allows traffic from source to destination
	PolicyRuleFlowDirect = PolicyRuleDirection("direct")
	// PolicyRuleFlowBidirect allows traffic to both directions
	PolicyRuleFlowBidirect = PolicyRuleDirection("bidirect")
)

const (
	// DefaultRuleName is a name for the Default rule that is created for every account
	DefaultRuleName = "Default"
	// DefaultRuleDescription is a description for the Default rule that is created for every account
	DefaultRuleDescription = "This is a default rule that allows connections between all the resources"
	// DefaultPolicyName is a name for the Default policy that is created for every account
	DefaultPolicyName = "Default"
	// DefaultPolicyDescription is a description for the Default policy that is created for every account
	DefaultPolicyDescription = "This is a default policy that allows connections between all the resources"
)

// PolicyUpdateOperation operation object with type and values to be applied
type PolicyUpdateOperation struct {
	Type   PolicyUpdateOperationType
	Values []string
}

// Policy of the Rego query
type Policy struct {
	// ID of the policy'
	ID string `gorm:"primaryKey"`

	PublicID string `json:"-"`

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name of the Policy
	Name string

	// Description of the policy visible in the UI
	Description string

	// Enabled status of the policy
	Enabled bool

	// Rules of the policy
	Rules []*PolicyRule `gorm:"foreignKey:PolicyID;references:id;constraint:OnDelete:CASCADE;"`

	// SourcePostureChecks are ID references to Posture checks for policy source groups
	SourcePostureChecks []string `gorm:"serializer:json"`
}

// Copy returns a copy of the policy.
func (p *Policy) Copy() *Policy {
	c := &Policy{
		ID:                  p.ID,
		AccountID:           p.AccountID,
		PublicID:            p.PublicID,
		Name:                p.Name,
		Description:         p.Description,
		Enabled:             p.Enabled,
		Rules:               make([]*PolicyRule, len(p.Rules)),
		SourcePostureChecks: make([]string, len(p.SourcePostureChecks)),
	}
	for i, r := range p.Rules {
		c.Rules[i] = r.Copy()
	}
	copy(c.SourcePostureChecks, p.SourcePostureChecks)
	return c
}

func (p *Policy) Equal(other *Policy) bool {
	if p == nil || other == nil {
		return p == other
	}

	if p.ID != other.ID ||
		p.AccountID != other.AccountID ||
		p.Name != other.Name ||
		p.Description != other.Description ||
		p.Enabled != other.Enabled {
		return false
	}

	if !stringSlicesEqualUnordered(p.SourcePostureChecks, other.SourcePostureChecks) {
		return false
	}

	if len(p.Rules) != len(other.Rules) {
		return false
	}

	otherRules := make(map[string]*PolicyRule, len(other.Rules))
	for _, r := range other.Rules {
		otherRules[r.ID] = r
	}
	for _, r := range p.Rules {
		otherRule, ok := otherRules[r.ID]
		if !ok {
			return false
		}
		if !r.Equal(otherRule) {
			return false
		}
	}

	return true
}

// EventMeta returns activity event meta related to this policy
func (p *Policy) EventMeta() map[string]any {
	return map[string]any{"name": p.Name}
}

// UpgradeAndFix different version of policies to latest version
func (p *Policy) UpgradeAndFix() {
	for _, r := range p.Rules {
		// start migrate from version v0.20.3
		if r.Protocol == "" {
			r.Protocol = PolicyRuleProtocolALL
		}
		if r.Protocol == PolicyRuleProtocolALL && !r.Bidirectional {
			r.Bidirectional = true
		}
		// -- v0.20.4
	}
}

// RuleGroups returns a list of all groups referenced in the policy's rules,
// including sources and destinations.
func (p *Policy) RuleGroups() []string {
	groups := make([]string, 0)
	for _, rule := range p.Rules {
		groups = append(groups, rule.Sources...)
		groups = append(groups, rule.Destinations...)
	}

	return groups
}

// SourceGroups returns a slice of all unique source groups referenced in the policy's rules.
func (p *Policy) SourceGroups() []string {
	if len(p.Rules) == 1 {
		return p.Rules[0].Sources
	}
	groups := make(map[string]struct{}, len(p.Rules))
	for _, rule := range p.Rules {
		for _, source := range rule.Sources {
			groups[source] = struct{}{}
		}
	}

	groupIDs := make([]string, 0, len(groups))
	for groupID := range groups {
		groupIDs = append(groupIDs, groupID)
	}

	return groupIDs
}
