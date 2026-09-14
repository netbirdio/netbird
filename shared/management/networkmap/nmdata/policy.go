package nmdata

const (
	policyRuleProtocolALL = "all"
	policyRuleProtocolTCP = "tcp"

	defaultSSHPortString        = "22"
	nativeSSHPortString         = "22022"
	defaultSSHPortNumber uint16 = 22
	nativeSSHPortNumber  uint16 = 22022
)

// Policy is the slim twin of types.Policy.
type Policy struct {
	ID                  string
	PublicID            string
	Enabled             bool
	SourcePostureChecks []string
	Rules               []*PolicyRule
}

// PolicyRule is the slim twin of types.PolicyRule.
type PolicyRule struct {
	ID                  string
	PolicyID            string
	Enabled             bool
	Action              string
	Protocol            string
	Bidirectional       bool
	Sources             []string
	Destinations        []string
	SourceResource      Resource
	DestinationResource Resource
	Ports               []string
	PortRanges          []RulePortRange
	AuthorizedGroups    map[string][]string
	AuthorizedUser      string
}

// RulePortRange is the slim twin of types.RulePortRange.
type RulePortRange struct {
	Start uint16
	End   uint16
}

// Resource is the slim twin of types.Resource.
type Resource struct {
	ID   string
	Type string
}

func (p *Policy) SourceGroups() []string {
	if len(p.Rules) == 1 && p.Rules[0] != nil {
		return p.Rules[0].Sources
	}
	groups := make(map[string]struct{}, len(p.Rules))
	for _, rule := range p.Rules {
		if rule == nil {
			continue
		}
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

// PolicyRuleImpliesLegacySSH is the twin-typed sibling of types.PolicyRuleImpliesLegacySSH.
func PolicyRuleImpliesLegacySSH(rule *PolicyRule) bool {
	return rule.Protocol == policyRuleProtocolALL ||
		(rule.Protocol == policyRuleProtocolTCP && (portsIncludesSSH(rule.Ports) || portRangeIncludesSSH(rule.PortRanges)))
}

func portRangeIncludesSSH(portRanges []RulePortRange) bool {
	for _, pr := range portRanges {
		if (pr.Start <= defaultSSHPortNumber && pr.End >= defaultSSHPortNumber) || (pr.Start <= nativeSSHPortNumber && pr.End >= nativeSSHPortNumber) {
			return true
		}
	}
	return false
}

func portsIncludesSSH(ports []string) bool {
	for _, port := range ports {
		if port == defaultSSHPortString || port == nativeSSHPortString {
			return true
		}
	}
	return false
}
