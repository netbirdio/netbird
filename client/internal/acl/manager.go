package acl

import (
	"net"
	"strconv"

	"github.com/netbirdio/netbird/client/firewall"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	log "github.com/sirupsen/logrus"
)

// Manager is a ACL rules manager
type Manager interface {
	ApplyFiltering(rules []*mgmProto.FirewallRule)
	Stop()
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	manager firewall.Manager
	rules   map[string]firewall.Rule
}

// ApplyFiltering firewall rules to the local firewall manager processed by ACL policy.
func (d *DefaultManager) ApplyFiltering(rules []*mgmProto.FirewallRule) {
	if d.manager == nil {
		log.Debug("firewall manager is not supported, skipping firewall rules")
		return
	}

	var (
		applyFailed bool
		newRules    = make(map[string]firewall.Rule)
	)
	for _, r := range rules {
		rule := d.protoRuleToFirewallRule(r)
		if rule == nil {
			log.Errorf("failed to apply firewall rule: %+v", r)
			applyFailed = true
			break
		}
		newRules[rule.GetRuleID()] = rule
	}
	if applyFailed {
		log.Error("failed to apply firewall rules, rollback ACL to previous state")
		for _, rule := range newRules {
			if err := d.manager.DeleteRule(rule); err != nil {
				log.Errorf("failed to delete new firewall rule (id: %v) during rollback: %v", rule.GetRuleID(), err)
				continue
			}
		}
		return
	}

	for ruleID, rule := range d.rules {
		if _, ok := newRules[ruleID]; !ok {
			if err := d.manager.DeleteRule(rule); err != nil {
				log.Errorf("failed to delete firewall rule: %v", err)
				continue
			}
			delete(d.rules, ruleID)
		}
	}
	d.rules = newRules
}

// Stop ACL controller and clear firewall state
func (a *DefaultManager) Stop() {
	if err := a.manager.Reset(); err != nil {
		log.WithError(err).Error("reset firewall state")
	}
}

func (d *DefaultManager) protoRuleToFirewallRule(r *mgmProto.FirewallRule) firewall.Rule {
	ip := net.ParseIP(r.PeerIP)
	if ip == nil {
		log.Error("invalid IP address, skipping firewall rule")
		return nil
	}

	var port *firewall.Port
	if r.Port != "" {
		value, err := strconv.Atoi(r.Port)
		if err != nil {
			log.Debug("invalid port, skipping firewall rule")
			return nil
		}
		port = &firewall.Port{
			Values: []int{value},
		}
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

	rule, err := d.manager.AddFiltering(ip, protocol, port, direction, action, "")
	if err != nil {
		log.Errorf("failed to add firewall rule: %v", err)
		return nil
	}
	d.rules[rule.GetRuleID()] = rule
	return rule
}
