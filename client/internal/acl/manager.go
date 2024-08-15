package acl

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/ssh"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// Manager is a ACL rules manager
type Manager interface {
	ApplyFiltering(networkMap *mgmProto.NetworkMap)
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	firewall       firewall.Manager
	ipsetCounter   int
	peerRulesPairs map[id.RuleID][]firewall.Rule
	routeRules     map[id.RuleID]struct{}
	mutex          sync.Mutex
}

func NewDefaultManager(fm firewall.Manager) *DefaultManager {
	return &DefaultManager{
		firewall:       fm,
		peerRulesPairs: make(map[id.RuleID][]firewall.Rule),
		routeRules:     make(map[id.RuleID]struct{}),
	}
}

// ApplyFiltering firewall rules to the local firewall manager processed by ACL policy.
//
// If allowByDefault is true it appends allow ALL traffic rules to input and output chains.
func (d *DefaultManager) ApplyFiltering(networkMap *mgmProto.NetworkMap) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	start := time.Now()
	defer func() {
		total := 0
		for _, pairs := range d.peerRulesPairs {
			total += len(pairs)
		}
		log.Infof(
			"ACL rules processed in: %v, total rules count: %d",
			time.Since(start), total)
	}()

	if d.firewall == nil {
		log.Debug("firewall manager is not supported, skipping firewall rules")
		return
	}

	d.applyPeerACLs(networkMap)

	// If we got empty rules list but management did not set the networkMap.FirewallRulesIsEmpty flag,
	// then the mgmt server is older than the client, and we need to allow all traffic for routes
	isLegacy := len(networkMap.RoutesFirewallRules) == 0 && !networkMap.RoutesFirewallRulesIsEmpty
	if err := d.firewall.SetLegacyManagement(isLegacy); err != nil {
		log.Errorf("failed to set legacy management flag: %v", err)
	}

	if err := d.applyRouteACLs(networkMap.RoutesFirewallRules); err != nil {
		log.Errorf("Failed to apply route ACLs: %v", err)
	}

	if err := d.firewall.Flush(); err != nil {
		log.Error("failed to flush firewall rules: ", err)
	}
}

func (d *DefaultManager) applyPeerACLs(networkMap *mgmProto.NetworkMap) {
	rules, squashedProtocols := d.squashAcceptRules(networkMap)

	enableSSH := networkMap.PeerConfig != nil &&
		networkMap.PeerConfig.SshConfig != nil &&
		networkMap.PeerConfig.SshConfig.SshEnabled
	if _, ok := squashedProtocols[mgmProto.RuleProtocol_ALL]; ok {
		enableSSH = enableSSH && !ok
	}
	if _, ok := squashedProtocols[mgmProto.RuleProtocol_TCP]; ok {
		enableSSH = enableSSH && !ok
	}

	// if TCP protocol rules not squashed and SSH enabled
	// we add default firewall rule which accepts connection to any peer
	// in the network by SSH (TCP 22 port).
	if enableSSH {
		rules = append(rules, &mgmProto.FirewallRule{
			PeerIP:    "0.0.0.0",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      strconv.Itoa(ssh.DefaultSSHPort),
		})
	}

	// if we got empty rules list but management not set networkMap.FirewallRulesIsEmpty flag
	// we have old version of management without rules handling, we should allow all traffic
	if len(networkMap.FirewallRules) == 0 && !networkMap.FirewallRulesIsEmpty {
		log.Warn("this peer is connected to a NetBird Management service with an older version. Allowing all traffic from connected peers")
		rules = append(rules,
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
		)
	}

	newRulePairs := make(map[id.RuleID][]firewall.Rule)
	ipsetByRuleSelectors := make(map[string]string)

	for _, r := range rules {
		// if this rule is member of rule selection with more than DefaultIPsCountForSet
		// it's IP address can be used in the ipset for firewall manager which supports it
		selector := d.getRuleGroupingSelector(r)
		ipsetName, ok := ipsetByRuleSelectors[selector]
		if !ok {
			d.ipsetCounter++
			ipsetName = fmt.Sprintf("nb%07d", d.ipsetCounter)
			ipsetByRuleSelectors[selector] = ipsetName
		}
		pairID, rulePair, err := d.protoRuleToFirewallRule(r, ipsetName)
		if err != nil {
			log.Errorf("failed to apply firewall rule: %+v, %v", r, err)
			d.rollBack(newRulePairs)
			break
		}
		if len(rules) > 0 {
			d.peerRulesPairs[pairID] = rulePair
			newRulePairs[pairID] = rulePair
		}
	}

	for pairID, rules := range d.peerRulesPairs {
		if _, ok := newRulePairs[pairID]; !ok {
			for _, rule := range rules {
				if err := d.firewall.DeletePeerRule(rule); err != nil {
					log.Errorf("failed to delete peer firewall rule: %v", err)
					continue
				}
			}
			delete(d.peerRulesPairs, pairID)
		}
	}
	d.peerRulesPairs = newRulePairs
}

func (d *DefaultManager) applyRouteACLs(rules []*mgmProto.RouteFirewallRule) error {
	var newRouteRules = make(map[id.RuleID]struct{})
	for _, rule := range rules {
		id, err := d.applyRouteACL(rule)
		if err != nil {
			return fmt.Errorf("apply route ACL: %w", err)
		}
		newRouteRules[id] = struct{}{}
	}

	for id := range d.routeRules {
		if _, ok := newRouteRules[id]; !ok {
			if err := d.firewall.DeleteRouteRule(id); err != nil {
				log.Errorf("failed to delete route firewall rule: %v", err)
				continue
			}
			delete(d.routeRules, id)
		}
	}
	d.routeRules = newRouteRules
	return nil
}

func (d *DefaultManager) applyRouteACL(rule *mgmProto.RouteFirewallRule) (id.RuleID, error) {
	if len(rule.SourceRanges) == 0 {
		return "", fmt.Errorf("source ranges is empty")
	}

	var sources []netip.Prefix
	for _, sourceRange := range rule.SourceRanges {
		source, err := netip.ParsePrefix(sourceRange)
		if err != nil {
			return "", fmt.Errorf("parse source range: %w", err)
		}
		sources = append(sources, source)
	}

	var destination netip.Prefix
	if rule.IsDynamic {
		destination = getDefault(sources[0])
	} else {
		var err error
		destination, err = netip.ParsePrefix(rule.Destination)
		if err != nil {
			return "", fmt.Errorf("parse destination: %w", err)
		}
	}

	protocol, err := convertToFirewallProtocol(rule.Protocol)
	if err != nil {
		return "", fmt.Errorf("invalid protocol: %w", err)
	}

	action, err := convertFirewallAction(rule.Action)
	if err != nil {
		return "", fmt.Errorf("invalid action: %w", err)
	}

	dPorts := convertPortInfo(rule.PortInfo)
	direction := firewall.RuleDirection(rule.Direction)

	addedRule, err := d.firewall.AddRouteFiltering(
		sources,
		destination,
		protocol,
		nil,
		dPorts,
		direction,
		action,
	)
	if err != nil {
		return "", fmt.Errorf("add route rule: %w", err)
	}

	return id.RuleID(addedRule.GetRuleID()), nil
}

func (d *DefaultManager) protoRuleToFirewallRule(
	r *mgmProto.FirewallRule,
	ipsetName string,
) (id.RuleID, []firewall.Rule, error) {
	ip := net.ParseIP(r.PeerIP)
	if ip == nil {
		return "", nil, fmt.Errorf("invalid IP address, skipping firewall rule")
	}

	protocol, err := convertToFirewallProtocol(r.Protocol)
	if err != nil {
		return "", nil, fmt.Errorf("skipping firewall rule: %s", err)
	}

	action, err := convertFirewallAction(r.Action)
	if err != nil {
		return "", nil, fmt.Errorf("skipping firewall rule: %s", err)
	}

	var port *firewall.Port
	if r.Port != "" {
		value, err := strconv.Atoi(r.Port)
		if err != nil {
			return "", nil, fmt.Errorf("invalid port, skipping firewall rule")
		}
		port = &firewall.Port{
			Values: []int{value},
		}
	}

	ruleID := d.getPeerRuleID(ip, protocol, int(r.Direction), port, action, "")
	if rulesPair, ok := d.peerRulesPairs[ruleID]; ok {
		return ruleID, rulesPair, nil
	}

	var rules []firewall.Rule
	switch r.Direction {
	case mgmProto.RuleDirection_IN:
		rules, err = d.addInRules(ip, protocol, port, action, ipsetName, "")
	case mgmProto.RuleDirection_OUT:
		rules, err = d.addOutRules(ip, protocol, port, action, ipsetName, "")
	default:
		return "", nil, fmt.Errorf("invalid direction, skipping firewall rule")
	}

	if err != nil {
		return "", nil, err
	}

	return ruleID, rules, nil
}

func (d *DefaultManager) addInRules(
	ip net.IP,
	protocol firewall.Protocol,
	port *firewall.Port,
	action firewall.Action,
	ipsetName string,
	comment string,
) ([]firewall.Rule, error) {
	var rules []firewall.Rule
	rule, err := d.firewall.AddPeerFiltering(
		ip, protocol, nil, port, firewall.RuleDirectionIN, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.firewall.AddPeerFiltering(
		ip, protocol, port, nil, firewall.RuleDirectionOUT, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	return append(rules, rule...), nil
}

func (d *DefaultManager) addOutRules(
	ip net.IP,
	protocol firewall.Protocol,
	port *firewall.Port,
	action firewall.Action,
	ipsetName string,
	comment string,
) ([]firewall.Rule, error) {
	var rules []firewall.Rule
	rule, err := d.firewall.AddPeerFiltering(
		ip, protocol, nil, port, firewall.RuleDirectionOUT, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.firewall.AddPeerFiltering(
		ip, protocol, port, nil, firewall.RuleDirectionIN, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	return append(rules, rule...), nil
}

// getPeerRuleID() returns unique ID for the rule based on its parameters.
func (d *DefaultManager) getPeerRuleID(
	ip net.IP,
	proto firewall.Protocol,
	direction int,
	port *firewall.Port,
	action firewall.Action,
	comment string,
) id.RuleID {
	idStr := ip.String() + string(proto) + strconv.Itoa(direction) + strconv.Itoa(int(action)) + comment
	if port != nil {
		idStr += port.String()
	}

	return id.RuleID(hex.EncodeToString(md5.New().Sum([]byte(idStr))))
}

// squashAcceptRules does complex logic to convert many rules which allows connection by traffic type
// to all peers in the network map to one rule which just accepts that type of the traffic.
//
// NOTE: It will not squash two rules for same protocol if one covers all peers in the network,
// but other has port definitions or has drop policy.
func (d *DefaultManager) squashAcceptRules(
	networkMap *mgmProto.NetworkMap,
) ([]*mgmProto.FirewallRule, map[mgmProto.RuleProtocol]struct{}) {
	totalIPs := 0
	for _, p := range append(networkMap.RemotePeers, networkMap.OfflinePeers...) {
		for range p.AllowedIps {
			totalIPs++
		}
	}

	type protoMatch map[mgmProto.RuleProtocol]map[string]int

	in := protoMatch{}
	out := protoMatch{}

	// trace which type of protocols was squashed
	squashedRules := []*mgmProto.FirewallRule{}
	squashedProtocols := map[mgmProto.RuleProtocol]struct{}{}

	// this function we use to do calculation, can we squash the rules by protocol or not.
	// We summ amount of Peers IP for given protocol we found in original rules list.
	// But we zeroed the IP's for protocol if:
	// 1. Any of the rule has DROP action type.
	// 2. Any of rule contains Port.
	//
	// We zeroed this to notify squash function that this protocol can't be squashed.
	addRuleToCalculationMap := func(i int, r *mgmProto.FirewallRule, protocols protoMatch) {
		drop := r.Action == mgmProto.RuleAction_DROP || r.Port != ""
		if drop {
			protocols[r.Protocol] = map[string]int{}
			return
		}
		if _, ok := protocols[r.Protocol]; !ok {
			protocols[r.Protocol] = map[string]int{}
		}

		// special case, when we receive this all network IP address
		// it means that rules for that protocol was already optimized on the
		// management side
		if r.PeerIP == "0.0.0.0" {
			squashedRules = append(squashedRules, r)
			squashedProtocols[r.Protocol] = struct{}{}
			return
		}

		ipset := protocols[r.Protocol]

		if _, ok := ipset[r.PeerIP]; ok {
			return
		}
		ipset[r.PeerIP] = i
	}

	for i, r := range networkMap.FirewallRules {
		// calculate squash for different directions
		if r.Direction == mgmProto.RuleDirection_IN {
			addRuleToCalculationMap(i, r, in)
		} else {
			addRuleToCalculationMap(i, r, out)
		}
	}

	// order of squashing by protocol is important
	// only for their first element ALL, it must be done first
	protocolOrders := []mgmProto.RuleProtocol{
		mgmProto.RuleProtocol_ALL,
		mgmProto.RuleProtocol_ICMP,
		mgmProto.RuleProtocol_TCP,
		mgmProto.RuleProtocol_UDP,
	}

	squash := func(matches protoMatch, direction mgmProto.RuleDirection) {
		for _, protocol := range protocolOrders {
			if ipset, ok := matches[protocol]; !ok || len(ipset) != totalIPs || len(ipset) < 2 {
				// don't squash if :
				// 1. Rules not cover all peers in the network
				// 2. Rules cover only one peer in the network.
				continue
			}

			// add special rule 0.0.0.0 which allows all IP's in our firewall implementations
			squashedRules = append(squashedRules, &mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: direction,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  protocol,
			})
			squashedProtocols[protocol] = struct{}{}

			if protocol == mgmProto.RuleProtocol_ALL {
				// if we have ALL traffic type squashed rule
				// it allows all other type of traffic, so we can stop processing
				break
			}
		}
	}

	squash(in, mgmProto.RuleDirection_IN)
	squash(out, mgmProto.RuleDirection_OUT)

	// if all protocol was squashed everything is allow and we can ignore all other rules
	if _, ok := squashedProtocols[mgmProto.RuleProtocol_ALL]; ok {
		return squashedRules, squashedProtocols
	}

	if len(squashedRules) == 0 {
		return networkMap.FirewallRules, squashedProtocols
	}

	var rules []*mgmProto.FirewallRule
	// filter out rules which was squashed from final list
	// if we also have other not squashed rules.
	for i, r := range networkMap.FirewallRules {
		if _, ok := squashedProtocols[r.Protocol]; ok {
			if m, ok := in[r.Protocol]; ok && m[r.PeerIP] == i {
				continue
			} else if m, ok := out[r.Protocol]; ok && m[r.PeerIP] == i {
				continue
			}
		}
		rules = append(rules, r)
	}

	return append(rules, squashedRules...), squashedProtocols
}

// getRuleGroupingSelector takes all rule properties except IP address to build selector
func (d *DefaultManager) getRuleGroupingSelector(rule *mgmProto.FirewallRule) string {
	return fmt.Sprintf("%v:%v:%v:%s", strconv.Itoa(int(rule.Direction)), rule.Action, rule.Protocol, rule.Port)
}

func (d *DefaultManager) rollBack(newRulePairs map[id.RuleID][]firewall.Rule) {
	log.Debugf("rollback ACL to previous state")
	for _, rules := range newRulePairs {
		for _, rule := range rules {
			if err := d.firewall.DeletePeerRule(rule); err != nil {
				log.Errorf("failed to delete new firewall rule (id: %v) during rollback: %v", rule.GetRuleID(), err)
			}
		}
	}
}

func convertToFirewallProtocol(protocol mgmProto.RuleProtocol) (firewall.Protocol, error) {
	switch protocol {
	case mgmProto.RuleProtocol_TCP:
		return firewall.ProtocolTCP, nil
	case mgmProto.RuleProtocol_UDP:
		return firewall.ProtocolUDP, nil
	case mgmProto.RuleProtocol_ICMP:
		return firewall.ProtocolICMP, nil
	case mgmProto.RuleProtocol_ALL:
		return firewall.ProtocolALL, nil
	default:
		return firewall.ProtocolALL, fmt.Errorf("invalid protocol type: %s", protocol.String())
	}
}

func shouldSkipInvertedRule(protocol firewall.Protocol, port *firewall.Port) bool {
	return protocol == firewall.ProtocolALL || protocol == firewall.ProtocolICMP || port == nil
}

func convertFirewallAction(action mgmProto.RuleAction) (firewall.Action, error) {
	switch action {
	case mgmProto.RuleAction_ACCEPT:
		return firewall.ActionAccept, nil
	case mgmProto.RuleAction_DROP:
		return firewall.ActionDrop, nil
	default:
		return firewall.ActionDrop, fmt.Errorf("invalid action type: %d", action)
	}
}

func convertPortInfo(portInfo *mgmProto.PortInfo) *firewall.Port {
	if portInfo == nil {
		return nil
	}

	if portInfo.GetPort() != 0 {
		return &firewall.Port{
			Values: []int{int(portInfo.GetPort())},
		}
	}

	if portInfo.GetRange() != nil {
		return &firewall.Port{
			IsRange: true,
			Values:  []int{int(portInfo.GetRange().Start), int(portInfo.GetRange().End)},
		}
	}

	return nil
}

func getDefault(prefix netip.Prefix) netip.Prefix {
	if prefix.Addr().Is6() {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}
