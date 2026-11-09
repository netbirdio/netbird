package legacynmap

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbroute "github.com/netbirdio/netbird/route"
)

func GenerateRouteFirewallRules(ctx context.Context, route *nbroute.Route, rule *PolicyRule, groupPeers []*ComponentPeer, direction int, includeIPv6 bool) []*RouteFirewallRule {
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

func filterPeerAppliedZones(ctx context.Context, accountZones []*zones.Zone, peerGroups LookupMap) []nbdns.CustomZone {
	var customZones []nbdns.CustomZone

	if len(peerGroups) == 0 {
		return customZones
	}

	for _, zone := range accountZones {
		if !zone.Enabled || len(zone.Records) == 0 {
			continue
		}

		hasAccess := false
		for _, distGroupID := range zone.DistributionGroups {
			if _, found := peerGroups[distGroupID]; found {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			continue
		}

		simpleRecords := make([]nbdns.SimpleRecord, 0, len(zone.Records))
		for _, record := range zone.Records {
			var recordType int
			rData := record.Content

			switch record.Type {
			case records.RecordTypeA:
				recordType = int(dns.TypeA)
			case records.RecordTypeAAAA:
				recordType = int(dns.TypeAAAA)
			case records.RecordTypeCNAME:
				recordType = int(dns.TypeCNAME)
				rData = dns.Fqdn(record.Content)
			default:
				log.WithContext(ctx).Warnf("unknown DNS record type %s for record %s", record.Type, record.ID)
				continue
			}

			simpleRecords = append(simpleRecords, nbdns.SimpleRecord{
				Name:  dns.Fqdn(record.Name),
				Type:  recordType,
				Class: nbdns.DefaultClass,
				TTL:   record.TTL,
				RData: rData,
			})
		}

		customZones = append(customZones, nbdns.CustomZone{
			Domain:               dns.Fqdn(zone.Domain),
			Records:              simpleRecords,
			SearchDomainDisabled: !zone.EnableSearchDomain,
			NonAuthoritative:     true,
		})
	}

	return customZones
}

func getAllowedUserIDs(a *Account) map[string]struct{} {
	users := make(map[string]struct{})
	for _, nbUser := range a.Users {
		if !nbUser.IsBlocked() && !nbUser.IsServiceUser {
			users[nbUser.Id] = struct{}{}
		}
	}
	return users
}

func getUniquePeerIDsFromGroupsIDs(a *Account, ctx context.Context, groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups)) // we expect at least one peer per group as initial capacity
	for _, groupID := range groups {
		group := a.GetGroup(groupID)
		if group == nil {
			log.WithContext(ctx).Warnf("group %s doesn't exist under account %s, will continue map generation without it", groupID, a.Id)
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			return group.Peers
		}

		for _, peerID := range group.Peers {
			peerIDs[peerID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(peerIDs))
	for peerID := range peerIDs {
		ids = append(ids, peerID)
	}

	return ids
}

func forcesRoutingPeerDNSResolution(a *Account, peerID string, routers map[string]map[string]*routerTypes.NetworkRouter) bool {
	targeted := proxyTargetedDomainResourceIDs(a)
	if len(targeted) == 0 {
		return false
	}

	for _, resource := range a.NetworkResources {
		if resource == nil || !resource.Enabled || resource.Type != resourceTypes.Domain {
			continue
		}
		if _, ok := targeted[resource.ID]; !ok {
			continue
		}
		if _, isRouter := routers[resource.NetworkID][peerID]; isRouter {
			return true
		}
	}

	return false
}

func proxyTargetedDomainResourceIDs(a *Account) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, svc := range a.Services {
		if svc == nil || !svc.Enabled || svc.Terminated {
			continue
		}
		for _, target := range svc.Targets {
			if target == nil || !target.Enabled {
				continue
			}
			if target.TargetType == service.TargetTypeDomain {
				ids[target.TargetId] = struct{}{}
			}
		}
	}
	return ids
}

func splitPeerSourcesByFamily(groupPeers []*ComponentPeer) (v4, v6 []string) {
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

func generateRuleIDBase(rule *PolicyRule, baseRule RouteFirewallRule) string {
	return rule.ID + strings.Join(baseRule.SourceRanges, ",") + strconv.Itoa(FirewallRuleDirectionIN) + baseRule.Protocol + baseRule.Action
}
