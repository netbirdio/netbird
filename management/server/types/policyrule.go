package types

import (
	"slices"
	"sort"

	"github.com/netbirdio/netbird/shared/management/proto"
)

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

func (r *RulePortRange) ToProto() *proto.PortInfo {
	return &proto.PortInfo{
		PortSelection: &proto.PortInfo_Range_{
			Range: &proto.PortInfo_Range{
				Start: uint32(r.Start),
				End:   uint32(r.End),
			},
		},
	}
}

func (r *RulePortRange) Equal(other *RulePortRange) bool {
	return r.Start == other.Start && r.End == other.End
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

	// AuthorizedGroups is a map of groupIDs and their respective access to local users via ssh
	AuthorizedGroups map[string][]string `gorm:"serializer:json"`

	// AuthorizedUser is a list of userIDs that are authorized to access local resources via ssh
	AuthorizedUser string
}

// Copy returns a copy of a policy rule
func (pm *PolicyRule) Copy() *PolicyRule {
	rule := &PolicyRule{
		ID:                  pm.ID,
		PolicyID:            pm.PolicyID,
		Name:                pm.Name,
		Description:         pm.Description,
		Enabled:             pm.Enabled,
		Action:              pm.Action,
		Destinations:        make([]string, len(pm.Destinations)),
		DestinationResource: pm.DestinationResource,
		Sources:             make([]string, len(pm.Sources)),
		SourceResource:      pm.SourceResource,
		Bidirectional:       pm.Bidirectional,
		Protocol:            pm.Protocol,
		Ports:               make([]string, len(pm.Ports)),
		PortRanges:          make([]RulePortRange, len(pm.PortRanges)),
		AuthorizedGroups:    make(map[string][]string, len(pm.AuthorizedGroups)),
		AuthorizedUser:      pm.AuthorizedUser,
	}
	copy(rule.Destinations, pm.Destinations)
	copy(rule.Sources, pm.Sources)
	copy(rule.Ports, pm.Ports)
	copy(rule.PortRanges, pm.PortRanges)
	for k, v := range pm.AuthorizedGroups {
		rule.AuthorizedGroups[k] = make([]string, len(v))
		copy(rule.AuthorizedGroups[k], v)
	}
	return rule
}

func (pm *PolicyRule) Equal(other *PolicyRule) bool {
	if pm == nil || other == nil {
		return pm == other
	}

	if pm.ID != other.ID ||
		pm.PolicyID != other.PolicyID ||
		pm.Name != other.Name ||
		pm.Description != other.Description ||
		pm.Enabled != other.Enabled ||
		pm.Action != other.Action ||
		pm.Bidirectional != other.Bidirectional ||
		pm.Protocol != other.Protocol ||
		pm.SourceResource != other.SourceResource ||
		pm.DestinationResource != other.DestinationResource ||
		pm.AuthorizedUser != other.AuthorizedUser {
		return false
	}

	if !stringSlicesEqualUnordered(pm.Sources, other.Sources) {
		return false
	}
	if !stringSlicesEqualUnordered(pm.Destinations, other.Destinations) {
		return false
	}
	if !stringSlicesEqualUnordered(pm.Ports, other.Ports) {
		return false
	}
	if !portRangeSlicesEqualUnordered(pm.PortRanges, other.PortRanges) {
		return false
	}
	if !authorizedGroupsEqual(pm.AuthorizedGroups, other.AuthorizedGroups) {
		return false
	}

	return true
}

func (pm *PolicyRule) Normalize() {
	if pm == nil {
		return
	}
	slices.Sort(pm.Sources)
	slices.Sort(pm.Destinations)
	slices.Sort(pm.Ports)
	sort.Slice(pm.PortRanges, func(i, j int) bool {
		if pm.PortRanges[i].Start != pm.PortRanges[j].Start {
			return pm.PortRanges[i].Start < pm.PortRanges[j].Start
		}
		return pm.PortRanges[i].End < pm.PortRanges[j].End
	})
	for k, v := range pm.AuthorizedGroups {
		slices.Sort(v)
		pm.AuthorizedGroups[k] = v
	}
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	sorted1 := make([]string, len(a))
	sorted2 := make([]string, len(b))
	copy(sorted1, a)
	copy(sorted2, b)
	slices.Sort(sorted1)
	slices.Sort(sorted2)
	return slices.Equal(sorted1, sorted2)
}

func portRangeSlicesEqualUnordered(a, b []RulePortRange) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	cmp := func(x, y RulePortRange) int {
		if x.Start != y.Start {
			if x.Start < y.Start {
				return -1
			}
			return 1
		}
		if x.End != y.End {
			if x.End < y.End {
				return -1
			}
			return 1
		}
		return 0
	}
	sorted1 := make([]RulePortRange, len(a))
	sorted2 := make([]RulePortRange, len(b))
	copy(sorted1, a)
	copy(sorted2, b)
	slices.SortFunc(sorted1, cmp)
	slices.SortFunc(sorted2, cmp)
	return slices.EqualFunc(sorted1, sorted2, func(x, y RulePortRange) bool {
		return x.Start == y.Start && x.End == y.End
	})
}

func authorizedGroupsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !stringSlicesEqualUnordered(va, vb) {
			return false
		}
	}
	return true
}
