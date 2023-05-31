package acl

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	IsUserspaceBind() bool
	SetFiltering(iface.PacketFilter) error
}

// Manager is a ACL rules manager
type Manager interface {
	ApplyFiltering(rules []*mgmProto.FirewallRule)
	Stop()
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	manager    firewall.Manager
	rulesPairs map[string][]firewall.Rule
	mutex      sync.Mutex
}

// ApplyFiltering firewall rules to the local firewall manager processed by ACL policy.
func (d *DefaultManager) ApplyFiltering(rules []*mgmProto.FirewallRule) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.manager == nil {
		log.Debug("firewall manager is not supported, skipping firewall rules")
		return
	}

	var (
		applyFailed  bool
		newRulePairs = make(map[string][]firewall.Rule)
	)
	for _, r := range rules {
		rules, err := d.protoRuleToFirewallRule(r)
		if err != nil {
			log.Errorf("failed to apply firewall rule: %+v, %v", r, err)
			applyFailed = true
			break
		}
		newRulePairs[rules[0].GetRuleID()] = rules
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

	if shouldSkipInvertedRule(protocol) {
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

	if shouldSkipInvertedRule(protocol) {
		return rules, nil
	}

	rule, err = d.manager.AddFiltering(ip, protocol, port, nil, firewall.RuleDirectionIN, action, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	return append(rules, rule), nil
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

func shouldSkipInvertedRule(protocol firewall.Protocol) bool {
	return protocol == firewall.ProtocolALL || protocol == firewall.ProtocolICMP
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
