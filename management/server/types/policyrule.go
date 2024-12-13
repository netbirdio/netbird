package types

// PolicyUpdateOperationType operation type
type PolicyUpdateOperationType int

// PolicyTrafficActionType action type for the firewall
type PolicyTrafficActionType string

// PolicyRuleProtocolType type of traffic
type PolicyRuleProtocolType string

// PolicyRuleDirection direction of traffic
type PolicyRuleDirection string

// RulePortRange represents a range of ports for a firewall rule.
type RulePortRange struct {
	Start uint16
	End   uint16
}

// PolicyRule is the metadata of the policy
type PolicyRule struct {
	// ID of the policy rule
	ID string `gorm:"primaryKey"`

	// PolicyID is a reference to Policy that this object belongs
	PolicyID string `json:"-" gorm:"index"`

	// Name of the rule visible in the UI
	Name string

	// Description of the rule visible in the UI
	Description string

	// Enabled status of rule in the system
	Enabled bool

	// Action policy accept or drops packets
	Action PolicyTrafficActionType

	// Destinations policy destination groups
	Destinations []string `gorm:"serializer:json"`

	// DestinationResource policy destination resource that the rule is applied to
	DestinationResource Resource `gorm:"serializer:json"`

	// Sources policy source groups
	Sources []string `gorm:"serializer:json"`

	// SourceResource policy source resource that the rule is applied to
	SourceResource Resource `gorm:"serializer:json"`

	// Bidirectional define if the rule is applicable in both directions, sources, and destinations
	Bidirectional bool

	// Protocol type of the traffic
	Protocol PolicyRuleProtocolType

	// Ports or it ranges list
	Ports []string `gorm:"serializer:json"`

	// PortRanges a list of port ranges.
	PortRanges []RulePortRange `gorm:"serializer:json"`
}

// Copy returns a copy of a policy rule
func (pm *PolicyRule) Copy() *PolicyRule {
	rule := &PolicyRule{
		ID:            pm.ID,
		PolicyID:      pm.PolicyID,
		Name:          pm.Name,
		Description:   pm.Description,
		Enabled:       pm.Enabled,
		Action:        pm.Action,
		Destinations:  make([]string, len(pm.Destinations)),
		Sources:       make([]string, len(pm.Sources)),
		Bidirectional: pm.Bidirectional,
		Protocol:      pm.Protocol,
		Ports:         make([]string, len(pm.Ports)),
		PortRanges:    make([]RulePortRange, len(pm.PortRanges)),
	}
	copy(rule.Destinations, pm.Destinations)
	copy(rule.Sources, pm.Sources)
	copy(rule.Ports, pm.Ports)
	copy(rule.PortRanges, pm.PortRanges)
	return rule
}
