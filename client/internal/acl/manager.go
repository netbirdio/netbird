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

	var protocol firewall.Protocol
	switch r.Protocol {
	case "tcp":
		protocol = firewall.ProtocolTCP
	case "udp":
		protocol = firewall.ProtocolUDP
	case "icmp":
		protocol = firewall.ProtocolICMP
	case "all":
		protocol = firewall.ProtocolALL
	default:
		return nil, fmt.Errorf("invalid protocol, skipping firewall rule: %q", r.Protocol)
	}

	var direction firewall.Direction
	switch r.Direction {
	case "src":
		direction = firewall.DirectionSrc
	case "dst":
		direction = firewall.DirectionDst
	default:
		return nil, fmt.Errorf("invalid direction, skipping firewall rule")
	}

	var action firewall.Action
	switch r.Action {
	case "accept":
		action = firewall.ActionAccept
	case "drop":
		action = firewall.ActionDrop
	default:
		return nil, fmt.Errorf("invalid action, skipping firewall rule")
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
	rule, err := d.manager.AddFiltering(ip, protocol, nil, port, direction, action, "")
	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}
	rules = append(rules, rule)

	if port != nil {
		if direction == firewall.DirectionSrc {
			direction = firewall.DirectionDst
		} else {
			direction = firewall.DirectionSrc
		}

		rule, err = d.manager.AddFiltering(ip, protocol, port, nil, direction, action, "")
		if err != nil {
			return nil, fmt.Errorf("failed to add firewall rule: %v", err)
		}

		rules = append(rules, rule)
	}

	d.rulesPairs[rules[0].GetRuleID()] = rules
	return rules, nil
}
