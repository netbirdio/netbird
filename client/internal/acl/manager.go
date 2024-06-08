package acl

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/ssh"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// Manager is an ACL rules manager
type Manager interface {
	ApplyFiltering(networkMap *mgmProto.NetworkMap)
	ResetV6Acl() error
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	firewall     firewall.Manager
	ipsetCounter int
	rulesPairs   map[string][]firewall.Rule
	rulesPairs6  map[string][]firewall.Rule
	mutex        sync.Mutex
}

func NewDefaultManager(fm firewall.Manager) *DefaultManager {
	return &DefaultManager{
		firewall:    fm,
		rulesPairs:  make(map[string][]firewall.Rule),
		rulesPairs6: make(map[string][]firewall.Rule),
	}
}

func (d *DefaultManager) ResetV6Acl() error {
	for _, rules := range d.rulesPairs6 {
		for _, r := range rules {
			err := d.firewall.DeleteRule(r)
			if err != nil {
				return err
			}
		}
	}
	err := d.firewall.ResetV6Firewall()
	if err != nil {
		return err
	}
	d.rulesPairs6 = make(map[string][]firewall.Rule)

	return nil
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
		for _, pairs := range d.rulesPairs {
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

	defer func() {
		if err := d.firewall.Flush(); err != nil {
			log.Error("failed to flush firewall rules: ", err)
		}
	}()

	rules, squashedProtocols := d.squashAcceptRules(networkMap)

	enableSSH := (networkMap.PeerConfig != nil &&
		networkMap.PeerConfig.SshConfig != nil &&
		networkMap.PeerConfig.SshConfig.SshEnabled)
	if _, ok := squashedProtocols[mgmProto.FirewallRule_ALL]; ok {
		enableSSH = enableSSH && !ok
	}
	if _, ok := squashedProtocols[mgmProto.FirewallRule_TCP]; ok {
		enableSSH = enableSSH && !ok
	}

	// if TCP protocol rules not squashed and SSH enabled
	// we add default firewall rule which accepts connection to any peer
	// in the network by SSH (TCP 22 port).
	if enableSSH {
		rules = append(rules, &mgmProto.FirewallRule{
			PeerIP:    "0.0.0.0",
			PeerIP6:   "::",
			Direction: mgmProto.FirewallRule_IN,
			Action:    mgmProto.FirewallRule_ACCEPT,
			Protocol:  mgmProto.FirewallRule_TCP,
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
				PeerIP6:   "::",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				PeerIP6:   "::",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
		)
	}

	newRulePairs := make(map[string][]firewall.Rule)
	newRulePairs6 := make(map[string][]firewall.Rule)
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
		pairID, rulePair, rulePair6, err := d.protoRuleToFirewallRule(r, ipsetName)
		if err != nil {
			log.Errorf("failed to apply firewall rule: %+v, %v", r, err)
			d.rollBack(newRulePairs)
			break
		}
		if len(rules) > 0 {
			d.rulesPairs[pairID] = rulePair
			newRulePairs[pairID] = rulePair
			d.rulesPairs6[pairID] = rulePair6
			newRulePairs6[pairID] = rulePair6
		}
	}

	for pairID, rules := range d.rulesPairs {
		if _, ok := newRulePairs[pairID]; !ok {
			for _, rule := range rules {
				if err := d.firewall.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete firewall rule: %v", err)
					continue
				}
			}
			delete(d.rulesPairs, pairID)
		}
	}
	for pairID, rules := range d.rulesPairs6 {
		if _, ok := newRulePairs6[pairID]; !ok {
			for _, rule := range rules {
				if err := d.firewall.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete firewall rule: %v", err)
					continue
				}
			}
			delete(d.rulesPairs6, pairID)
		}
	}

	d.rulesPairs = newRulePairs
	d.rulesPairs6 = newRulePairs6
}

func (d *DefaultManager) protoRuleToFirewallRule(
	r *mgmProto.FirewallRule,
	ipsetName string,
) (string, []firewall.Rule, []firewall.Rule, error) {
	ip := net.ParseIP(r.PeerIP)
	if ip == nil {
		return "", nil, nil, fmt.Errorf("invalid IP address, skipping firewall rule")
	}

	var ip6 *net.IP = nil
	if d.firewall.V6Active() && r.PeerIP6 != "" {
		ip6tmp := net.ParseIP(r.PeerIP6)
		if ip6tmp == nil {
			return "", nil, nil, fmt.Errorf("invalid IP address, skipping firewall rule")
		}
		ip6 = &ip6tmp
	}

	protocol, err := convertToFirewallProtocol(r.Protocol)
	if err != nil {
		return "", nil, nil, fmt.Errorf("skipping firewall rule: %s", err)
	}

	action, err := convertFirewallAction(r.Action)
	if err != nil {
		return "", nil, nil, fmt.Errorf("skipping firewall rule: %s", err)
	}

	var port *firewall.Port
	if r.Port != "" {
		value, err := strconv.Atoi(r.Port)
		if err != nil {
			return "", nil, nil, fmt.Errorf("invalid port, skipping firewall rule")
		}
		port = &firewall.Port{
			Values: []int{value},
		}
	}

	var rules []firewall.Rule
	var rules6 []firewall.Rule

	ruleID := d.getRuleID(ip, ip6, protocol, int(r.Direction), port, action, "")
	if rulesPair, ok := d.rulesPairs[ruleID]; ok {
		rules = rulesPair
	}
	if rulesPair6, ok := d.rulesPairs6[ruleID]; d.firewall.V6Active() && ok && ip6 != nil {
		rules6 = rulesPair6
	}

	if rules == nil {
		switch r.Direction {
		case mgmProto.FirewallRule_IN:
			rules, err = d.addInRules(ip, protocol, port, action, ipsetName, "")
		case mgmProto.FirewallRule_OUT:
			rules, err = d.addOutRules(ip, protocol, port, action, ipsetName, "")
		default:
			return "", nil, nil, fmt.Errorf("invalid direction, skipping firewall rule")
		}
	}

	if err != nil {
		return "", nil, nil, err
	}

	if d.firewall.V6Active() && ip6 != nil && rules6 == nil {
		switch r.Direction {
		case mgmProto.FirewallRule_IN:
			rules6, err = d.addInRules(*ip6, protocol, port, action, ipsetName, "")
		case mgmProto.FirewallRule_OUT:
			rules6, err = d.addOutRules(*ip6, protocol, port, action, ipsetName, "")
		default:
			return "", nil, nil, fmt.Errorf("invalid direction, skipping firewall rule")
		}

	}

	if err != nil && err.Error() != "failed to add firewall rule: attempted to configure filtering for IPv6 address even though IPv6 is not active" {
		return "", rules, nil, err
	}

	return ruleID, rules, rules6, nil
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
	rule, err := d.firewall.AddFiltering(
		ip, protocol, nil, port, firewall.RuleDirectionIN, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.firewall.AddFiltering(
		ip, protocol, port, nil, firewall.RuleDirectionOUT, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	return rules, nil
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
	rule, err := d.firewall.AddFiltering(
		ip, protocol, nil, port, firewall.RuleDirectionOUT, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.firewall.AddFiltering(
		ip, protocol, port, nil, firewall.RuleDirectionIN, action, ipsetName, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule...)

	return rules, nil
}

// getRuleID() returns unique ID for the rule based on its parameters.
func (d *DefaultManager) getRuleID(
	ip net.IP,
	ip6 *net.IP,
	proto firewall.Protocol,
	direction int,
	port *firewall.Port,
	action firewall.Action,
	comment string,
) string {
	ip6Str := ""
	if ip6 != nil {
		ip6Str = ip6.String()
	}
	idStr := ip.String() + ip6Str + string(proto) + strconv.Itoa(direction) + strconv.Itoa(int(action)) + comment
	if port != nil {
		idStr += port.String()
	}

	return hex.EncodeToString(md5.New().Sum([]byte(idStr)))
}

// squashAcceptRules does complex logic to convert many rules which allows connection by traffic type
// to all peers in the network map to one rule which just accepts that type of the traffic.
//
// NOTE: It will not squash two rules for same protocol if one covers all peers in the network,
// but other has port definitions or has drop policy.
func (d *DefaultManager) squashAcceptRules(
	networkMap *mgmProto.NetworkMap,
) ([]*mgmProto.FirewallRule, map[mgmProto.FirewallRuleProtocol]struct{}) {
	totalIPs := 0
	for _, p := range append(networkMap.RemotePeers, networkMap.OfflinePeers...) {
		for range p.AllowedIps {
			totalIPs++
		}
	}

	type protoMatch map[mgmProto.FirewallRuleProtocol]map[string]int

	in := protoMatch{}
	out := protoMatch{}

	// trace which type of protocols was squashed
	squashedRules := []*mgmProto.FirewallRule{}
	squashedProtocols := map[mgmProto.FirewallRuleProtocol]struct{}{}

	// this function we use to do calculation, can we squash the rules by protocol or not.
	// We summ amount of Peers IP for given protocol we found in original rules list.
	// But we zeroed the IP's for protocol if:
	// 1. Any of the rule has DROP action type.
	// 2. Any of rule contains Port.
	//
	// We zeroed this to notify squash function that this protocol can't be squashed.
	addRuleToCalculationMap := func(i int, r *mgmProto.FirewallRule, protocols protoMatch) {
		drop := r.Action == mgmProto.FirewallRule_DROP || r.Port != ""
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
			// I don't _think_ that IPv6 is relevant here, as any optimization that has r.PeerIP6 == "::" should also
			// implicitly have r.PeerIP == "0.0.0.0".
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
		if r.Direction == mgmProto.FirewallRule_IN {
			addRuleToCalculationMap(i, r, in)
		} else {
			addRuleToCalculationMap(i, r, out)
		}
	}

	// order of squashing by protocol is important
	// only for their first element ALL, it must be done first
	protocolOrders := []mgmProto.FirewallRuleProtocol{
		mgmProto.FirewallRule_ALL,
		mgmProto.FirewallRule_ICMP,
		mgmProto.FirewallRule_TCP,
		mgmProto.FirewallRule_UDP,
	}

	squash := func(matches protoMatch, direction mgmProto.FirewallRuleDirection) {
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
				PeerIP6:   "::",
				Direction: direction,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  protocol,
			})
			squashedProtocols[protocol] = struct{}{}

			if protocol == mgmProto.FirewallRule_ALL {
				// if we have ALL traffic type squashed rule
				// it allows all other type of traffic, so we can stop processing
				break
			}
		}
	}

	squash(in, mgmProto.FirewallRule_IN)
	squash(out, mgmProto.FirewallRule_OUT)

	// if all protocol was squashed everything is allow and we can ignore all other rules
	if _, ok := squashedProtocols[mgmProto.FirewallRule_ALL]; ok {
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

func (d *DefaultManager) rollBack(newRulePairs map[string][]firewall.Rule) {
	log.Debugf("rollback ACL to previous state")
	for _, rules := range newRulePairs {
		for _, rule := range rules {
			if err := d.firewall.DeleteRule(rule); err != nil {
				log.Errorf("failed to delete new firewall rule (id: %v) during rollback: %v", rule.GetRuleID(), err)
			}
		}
	}
}

func convertToFirewallProtocol(protocol mgmProto.FirewallRuleProtocol) (firewall.Protocol, error) {
	switch protocol {
	case mgmProto.FirewallRule_TCP:
		return firewall.ProtocolTCP, nil
	case mgmProto.FirewallRule_UDP:
		return firewall.ProtocolUDP, nil
	case mgmProto.FirewallRule_ICMP:
		return firewall.ProtocolICMP, nil
	case mgmProto.FirewallRule_ALL:
		return firewall.ProtocolALL, nil
	default:
		return firewall.ProtocolALL, fmt.Errorf("invalid protocol type: %s", protocol.String())
	}
}

func shouldSkipInvertedRule(protocol firewall.Protocol, port *firewall.Port) bool {
	return protocol == firewall.ProtocolALL || protocol == firewall.ProtocolICMP || port == nil
}

func convertFirewallAction(action mgmProto.FirewallRuleAction) (firewall.Action, error) {
	switch action {
	case mgmProto.FirewallRule_ACCEPT:
		return firewall.ActionAccept, nil
	case mgmProto.FirewallRule_DROP:
		return firewall.ActionDrop, nil
	default:
		return firewall.ActionDrop, fmt.Errorf("invalid action type: %d", action)
	}
}
