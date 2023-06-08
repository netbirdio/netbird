package acl

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/iface"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
	SetFilter(iface.PacketFilter) error
}

// Manager is a ACL rules manager
type Manager interface {
	ApplyFiltering(networkMap *mgmProto.NetworkMap)
	Stop()
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	manager    firewall.Manager
	rulesPairs map[string][]firewall.Rule
	mutex      sync.Mutex
}

// ApplyFiltering firewall rules to the local firewall manager processed by ACL policy.
//
// If allowByDefault is ture it appends allow ALL traffic rules to input and output chains.
func (d *DefaultManager) ApplyFiltering(networkMap *mgmProto.NetworkMap) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.manager == nil {
		log.Debug("firewall manager is not supported, skipping firewall rules")
		return
	}

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
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
		)
	}

	applyFailed := false
	newRulePairs := make(map[string][]firewall.Rule)
	for _, r := range rules {
		rulePair, err := d.protoRuleToFirewallRule(r)
		if err != nil {
			log.Errorf("failed to apply firewall rule: %+v, %v", r, err)
			applyFailed = true
			break
		}
		newRulePairs[rulePair[0].GetRuleID()] = rulePair
	}
	if applyFailed {
		log.Error("failed to apply firewall rules, rollback ACL to previous state")
		for _, rules := range newRulePairs {
			for _, rule := range rules {
				if err := d.manager.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete new firewall rule (id: %v) during rollback: %v", rule.GetRuleID(), err)
					continue
				}
			}
		}
		return
	}

	for pairID, rules := range d.rulesPairs {
		if _, ok := newRulePairs[pairID]; !ok {
			for _, rule := range rules {
				if err := d.manager.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete firewall rule: %v", err)
					continue
				}
			}
			delete(d.rulesPairs, pairID)
		}
	}
	d.rulesPairs = newRulePairs
}

// Stop ACL controller and clear firewall state
func (d *DefaultManager) Stop() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if err := d.manager.Reset(); err != nil {
		log.WithError(err).Error("reset firewall state")
	}
}

func (d *DefaultManager) protoRuleToFirewallRule(r *mgmProto.FirewallRule) ([]firewall.Rule, error) {
	ip := net.ParseIP(r.PeerIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address, skipping firewall rule")
	}

	protocol := convertToFirewallProtocol(r.Protocol)
	if protocol == firewall.ProtocolUnknown {
		return nil, fmt.Errorf("invalid protocol type: %d, skipping firewall rule", r.Protocol)
	}

	action := convertFirewallAction(r.Action)
	if action == firewall.ActionUnknown {
		return nil, fmt.Errorf("invalid action type: %d, skipping firewall rule", r.Action)
	}

	var port *firewall.Port
	if r.Port != "" {
		value, err := strconv.Atoi(r.Port)
		if err != nil {
			return nil, fmt.Errorf("invalid port, skipping firewall rule")
		}
		port = &firewall.Port{
			Values: []int{value},
		}
	}

	var rules []firewall.Rule
	var err error
	switch r.Direction {
	case mgmProto.FirewallRule_IN:
		rules, err = d.addInRules(ip, protocol, port, action, "")
	case mgmProto.FirewallRule_OUT:
		rules, err = d.addOutRules(ip, protocol, port, action, "")
	default:
		return nil, fmt.Errorf("invalid direction, skipping firewall rule")
	}

	if err != nil {
		return nil, err
	}

	d.rulesPairs[rules[0].GetRuleID()] = rules
	return rules, nil
}

func (d *DefaultManager) addInRules(ip net.IP, protocol firewall.Protocol, port *firewall.Port, action firewall.Action, comment string) ([]firewall.Rule, error) {
	var rules []firewall.Rule
	rule, err := d.manager.AddFiltering(ip, protocol, nil, port, firewall.RuleDirectionIN, action, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.manager.AddFiltering(ip, protocol, port, nil, firewall.RuleDirectionOUT, action, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	return append(rules, rule), nil
}

func (d *DefaultManager) addOutRules(ip net.IP, protocol firewall.Protocol, port *firewall.Port, action firewall.Action, comment string) ([]firewall.Rule, error) {
	var rules []firewall.Rule
	rule, err := d.manager.AddFiltering(ip, protocol, nil, port, firewall.RuleDirectionOUT, action, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule)

	if shouldSkipInvertedRule(protocol, port) {
		return rules, nil
	}

	rule, err = d.manager.AddFiltering(ip, protocol, port, nil, firewall.RuleDirectionIN, action, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	return append(rules, rule), nil
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
	for _, p := range networkMap.RemotePeers {
		for range p.AllowedIps {
			totalIPs++
		}
	}

	type protoMatch map[mgmProto.FirewallRuleProtocol]map[string]int

	in := protoMatch{}
	out := protoMatch{}

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
		match := protocols[r.Protocol]

		if _, ok := match[r.PeerIP]; ok {
			return
		}
		match[r.PeerIP] = i
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
	// only for ther first element ALL, it must be done first
	protocolOrders := []mgmProto.FirewallRuleProtocol{
		mgmProto.FirewallRule_ALL,
		mgmProto.FirewallRule_ICMP,
		mgmProto.FirewallRule_TCP,
		mgmProto.FirewallRule_UDP,
	}

	// trace which type of protocols was squashed
	squashedRules := []*mgmProto.FirewallRule{}
	squashedProtocols := map[mgmProto.FirewallRuleProtocol]struct{}{}
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

func convertToFirewallProtocol(protocol mgmProto.FirewallRuleProtocol) firewall.Protocol {
	switch protocol {
	case mgmProto.FirewallRule_TCP:
		return firewall.ProtocolTCP
	case mgmProto.FirewallRule_UDP:
		return firewall.ProtocolUDP
	case mgmProto.FirewallRule_ICMP:
		return firewall.ProtocolICMP
	case mgmProto.FirewallRule_ALL:
		return firewall.ProtocolALL
	default:
		return firewall.ProtocolUnknown
	}
}

func shouldSkipInvertedRule(protocol firewall.Protocol, port *firewall.Port) bool {
	return protocol == firewall.ProtocolALL || protocol == firewall.ProtocolICMP || port == nil
}

func convertFirewallAction(action mgmProto.FirewallRuleAction) firewall.Action {
	switch action {
	case mgmProto.FirewallRule_ACCEPT:
		return firewall.ActionAccept
	case mgmProto.FirewallRule_DROP:
		return firewall.ActionDrop
	default:
		return firewall.ActionUnknown
	}
}
