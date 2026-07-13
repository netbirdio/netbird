package types

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbroute "github.com/netbirdio/netbird/route"
)

const (
	FirewallRuleDirectionIN  = 0
	FirewallRuleDirectionOUT = 1
)

// FirewallRule is a rule of the firewall.
type FirewallRule struct {
	// PolicyID is the ID of the policy this rule is derived from
	PolicyID string

	// PeerIP of the peer
	PeerIP string

	// Direction of the traffic
	Direction int

	// Action of the traffic
	Action string

	// Protocol of the traffic
	Protocol string

	// Port of the traffic
	Port string

	// PortRange represents the range of ports for a firewall rule
	PortRange RulePortRange
}

// Equal checks if two firewall rules are equal.
func (r *FirewallRule) Equal(other *FirewallRule) bool {
	return reflect.DeepEqual(r, other)
}

// generateRouteFirewallRules generates a list of firewall rules for a given route.
// For static routes, source ranges match the destination family (v4 or v6).
// For dynamic routes (domain-based), separate v4 and v6 rules are generated
// so the routing peer's forwarding chain allows both address families.
func generateRouteFirewallRules(ctx context.Context, route *nbroute.Route, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int, includeIPv6 bool) []*RouteFirewallRule {
	rulesExists := make(map[string]struct{})
	rules := make([]*RouteFirewallRule, 0)

	v4Sources, v6Sources := splitPeerSourcesByFamily(groupPeers)

	isV6Route := route.Network.Addr().Is6()

	// Skip v6 destination routes entirely for peers without IPv6 support
	if isV6Route && !includeIPv6 {
		return rules
	}

	// Pick sources matching the destination family
	sourceRanges := v4Sources
	if isV6Route {
		sourceRanges = v6Sources
	}

	baseRule := RouteFirewallRule{
		PolicyID:     rule.PolicyID,
		RouteID:      route.ID,
		SourceRanges: sourceRanges,
		Action:       string(rule.Action),
		Destination:  route.Network.String(),
		Protocol:     string(rule.Protocol),
		Domains:      route.Domains,
		IsDynamic:    route.IsDynamic(),
	}

	if len(rule.Ports) == 0 {
		rules = append(rules, generateRulesWithPortRanges(baseRule, rule, rulesExists)...)
	} else {
		rules = append(rules, generateRulesWithPorts(ctx, baseRule, rule, rulesExists)...)
	}

	// Generate v6 counterpart for dynamic routes and 0.0.0.0/0 exit node routes.
	isDefaultV4 := !isV6Route && route.Network.Bits() == 0
	if includeIPv6 && (route.IsDynamic() || isDefaultV4) && len(v6Sources) > 0 {
		v6Rule := baseRule
		v6Rule.SourceRanges = v6Sources
		if isDefaultV4 {
			v6Rule.Destination = "::/0"
			v6Rule.RouteID = route.ID + "-v6-default"
		}
		if len(rule.Ports) == 0 {
			rules = append(rules, generateRulesWithPortRanges(v6Rule, rule, rulesExists)...)
		} else {
			rules = append(rules, generateRulesWithPorts(ctx, v6Rule, rule, rulesExists)...)
		}
	}

	return rules
}

// splitPeerSourcesByFamily separates peer IPs into v4 (/32) and v6 (/128) source ranges.
func splitPeerSourcesByFamily(groupPeers []*nbpeer.Peer) (v4, v6 []string) {
	v4 = make([]string, 0, len(groupPeers))
	v6 = make([]string, 0, len(groupPeers))
	for _, peer := range groupPeers {
		if peer == nil {
			continue
		}
		v4 = append(v4, fmt.Sprintf(AllowedIPsFormat, peer.IP))
		if peer.IPv6.IsValid() {
			v6 = append(v6, fmt.Sprintf(AllowedIPsV6Format, peer.IPv6))
		}
	}
	return
}

// generateRulesForPeer generates rules for a given peer based on ports and port ranges.
func generateRulesWithPortRanges(baseRule RouteFirewallRule, rule *PolicyRule, rulesExists map[string]struct{}) []*RouteFirewallRule {
	rules := make([]*RouteFirewallRule, 0)

	ruleIDBase := generateRuleIDBase(rule, baseRule)
	if len(rule.Ports) == 0 {
		if len(rule.PortRanges) == 0 {
			if _, ok := rulesExists[ruleIDBase]; !ok {
				rulesExists[ruleIDBase] = struct{}{}
				rules = append(rules, &baseRule)
			}
		} else {
			for _, portRange := range rule.PortRanges {
				ruleID := fmt.Sprintf("%s%d-%d", ruleIDBase, portRange.Start, portRange.End)
				if _, ok := rulesExists[ruleID]; !ok {
					rulesExists[ruleID] = struct{}{}
					pr := baseRule
					pr.PortRange = portRange
					rules = append(rules, &pr)
				}
			}
		}
		return rules
	}

	return rules
}

// generateRulesWithPorts generates rules when specific ports are provided.
func generateRulesWithPorts(ctx context.Context, baseRule RouteFirewallRule, rule *PolicyRule, rulesExists map[string]struct{}) []*RouteFirewallRule {
	rules := make([]*RouteFirewallRule, 0)
	ruleIDBase := generateRuleIDBase(rule, baseRule)

	for _, port := range rule.Ports {
		ruleID := ruleIDBase + port
		if _, ok := rulesExists[ruleID]; ok {
			continue
		}
		rulesExists[ruleID] = struct{}{}

		pr := baseRule
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to parse port %s for rule: %s", port, rule.ID)
			continue
		}

		pr.Port = uint16(p)
		rules = append(rules, &pr)
	}

	return rules
}

// generateRuleIDBase generates the base rule ID for checking duplicates.
func generateRuleIDBase(rule *PolicyRule, baseRule RouteFirewallRule) string {
	return rule.ID + strings.Join(baseRule.SourceRanges, ",") + strconv.Itoa(FirewallRuleDirectionIN) + baseRule.Protocol + baseRule.Action
}
