package types

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// PolicyTrafficActionAccept indicates that the traffic is accepted
	PolicyTrafficActionAccept = PolicyTrafficActionType("accept")
	// PolicyTrafficActionDrop indicates that the traffic is dropped
	PolicyTrafficActionDrop = PolicyTrafficActionType("drop")
)

const (
	// PolicyRuleProtocolALL type of traffic
	PolicyRuleProtocolALL = PolicyRuleProtocolType("all")
	// PolicyRuleProtocolTCP type of traffic
	PolicyRuleProtocolTCP = PolicyRuleProtocolType("tcp")
	// PolicyRuleProtocolUDP type of traffic
	PolicyRuleProtocolUDP = PolicyRuleProtocolType("udp")
	// PolicyRuleProtocolICMP type of traffic
	PolicyRuleProtocolICMP = PolicyRuleProtocolType("icmp")
	// PolicyRuleProtocolNetbirdSSH type of traffic
	PolicyRuleProtocolNetbirdSSH = PolicyRuleProtocolType("netbird-ssh")
)

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

func ParseRuleString(rule string) (PolicyRuleProtocolType, RulePortRange, error) {
	rule = strings.TrimSpace(strings.ToLower(rule))
	if rule == "all" {
		return PolicyRuleProtocolALL, RulePortRange{}, nil
	}
	if rule == "icmp" {
		return PolicyRuleProtocolICMP, RulePortRange{}, nil
	}

	split := strings.Split(rule, "/")
	if len(split) != 2 {
		return "", RulePortRange{}, errors.New("invalid rule format: expected protocol/port or protocol/port-range")
	}

	protoStr := strings.TrimSpace(split[0])
	portStr := strings.TrimSpace(split[1])

	var protocol PolicyRuleProtocolType
	switch protoStr {
	case "tcp":
		protocol = PolicyRuleProtocolTCP
	case "udp":
		protocol = PolicyRuleProtocolUDP
	case "icmp":
		return "", RulePortRange{}, errors.New("icmp does not accept ports; use 'icmp' without '/…'")
	case "netbird-ssh":
		return PolicyRuleProtocolNetbirdSSH, RulePortRange{Start: nativeSSHPortNumber, End: nativeSSHPortNumber}, nil
	default:
		return "", RulePortRange{}, fmt.Errorf("invalid protocol: %q", protoStr)
	}

	portRange, err := parsePortRange(portStr)
	if err != nil {
		return "", RulePortRange{}, err
	}

	return protocol, portRange, nil
}

func parsePortRange(portStr string) (RulePortRange, error) {
	if strings.Contains(portStr, "-") {
		rangeParts := strings.Split(portStr, "-")
		if len(rangeParts) != 2 {
			return RulePortRange{}, fmt.Errorf("invalid port range %q", portStr)
		}
		start, err := parsePort(strings.TrimSpace(rangeParts[0]))
		if err != nil {
			return RulePortRange{}, err
		}
		end, err := parsePort(strings.TrimSpace(rangeParts[1]))
		if err != nil {
			return RulePortRange{}, err
		}
		if start > end {
			return RulePortRange{}, fmt.Errorf("invalid port range: start %d > end %d", start, end)
		}
		return RulePortRange{Start: uint16(start), End: uint16(end)}, nil
	}

	p, err := parsePort(portStr)
	if err != nil {
		return RulePortRange{}, err
	}

	return RulePortRange{Start: uint16(p), End: uint16(p)}, nil
}

func parsePort(portStr string) (int, error) {

	if portStr == "" {
		return 0, errors.New("empty port")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port out of range (1–65535): %d", p)
	}
	return p, nil
}
