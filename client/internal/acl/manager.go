package acl

import (
	"net"
	"strconv"
	"sync"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
	mgmProto "github.com/netbirdio/netbird/management/proto"

	log "github.com/sirupsen/logrus"
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
		applyFailed bool
		newRules    = make(map[string][]firewall.Rule)
	)
	for _, r := range rules {
		rules := d.protoRuleToFirewallRule(r)
		if len(rules) == 0 {
			log.Errorf("failed to apply firewall rule: %+v", r)
			applyFailed = true
			break
		}
		newRules[rules[0].GetRuleID()] = rules
	}
	if applyFailed {
		log.Error("failed to apply firewall rules, rollback ACL to previous state")
		for _, rules := range newRules {
			for _, rule := range rules {
				if err := d.manager.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete new firewall rule (id: %v) during rollback: %v", rule.GetRuleID(), err)
					continue
				}
			}
		}
		return
	}

	for ruleID, rules := range d.rulesPairs {
		if _, ok := newRules[ruleID]; !ok {
			for _, rule := range rules {
				if err := d.manager.DeleteRule(rule); err != nil {
					log.Errorf("failed to delete firewall rule: %v", err)
					continue
				}
			}
			delete(d.rulesPairs, ruleID)
		}
	}
	d.rulesPairs = newRules
}

// Stop ACL controller and clear firewall state
func (d *DefaultManager) Stop() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if err := d.manager.Reset(); err != nil {
		log.WithError(err).Error("reset firewall state")
	}
}

func (d *DefaultManager) protoRuleToFirewallRule(r *mgmProto.FirewallRule) []firewall.Rule {
	ip := net.ParseIP(r.PeerIP)
	if ip == nil {
		log.Error("invalid IP address, skipping firewall rule")
		return nil
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
		log.Errorf("invalid protocol, skipping firewall rule: %q", r.Protocol)
		return nil
	}

	var direction firewall.Direction
	switch r.Direction {
	case "src":
		direction = firewall.DirectionSrc
	case "dst":
		direction = firewall.DirectionDst
	default:
		log.Error("invalid direction, skipping firewall rule")
		return nil
	}

	var action firewall.Action
	switch r.Action {
	case "accept":
		action = firewall.ActionAccept
	case "drop":
		action = firewall.ActionDrop
	default:
		log.Error("invalid action, skipping firewall rule")
		return nil
	}

	var dPort, sPort *firewall.Port
	if r.Port != "" {
		value, err := strconv.Atoi(r.Port)
		if err != nil {
			log.Debug("invalid port, skipping firewall rule")
			return nil
		}
		p := &firewall.Port{
			Values: []int{value},
		}

		if direction == firewall.DirectionSrc {
			dPort = p
		} else {
			sPort = p
		}
	}

	var rules []firewall.Rule
	rule, err := d.manager.AddFiltering(ip, protocol, sPort, dPort, direction, action, "")
	if err != nil {
		log.Errorf("failed to add firewall rule: %v", err)
		return nil
	}
	ruleID := rule.GetRuleID()
	rules = append(rules, rule)

	if sPort != nil || dPort != nil {
		rule, err = d.manager.AddFiltering(ip, protocol, dPort, sPort, direction, action, "")
		if err != nil {
			log.Errorf("failed to add firewall rule: %v", err)
			return nil
		}
		rules = append(rules, rule)
	}

	d.rulesPairs[ruleID] = rules
	return rules
}
