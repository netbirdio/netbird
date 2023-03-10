package iptables

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/coreos/go-iptables/iptables"

	fw "github.com/netbirdio/netbird/client/firewall"
)

const (
	chainFilterName = "NETBIRD-ACL"
)

// Manager of iptables firewall
type Manager struct {
	mutex   *sync.Mutex
	ruleCnt int

	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
}

// Create iptables firewall manager
func Create() (*Manager, error) {
	m := &Manager{}

	// init clients for booth ipv4 and ipv6
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not supported")
	}
	m.ipv4Client = ipv4Client

	ipv6Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("ip6tables is not installed in the system or not supported")
	}
	m.ipv6Client = ipv6Client

	if err := m.Reset(); err != nil {
		return nil, fmt.Errorf("failed to reset firewall: %s", err)
	}

	return m, nil
}

// AddFiltering adds a filtering rule to the firewall
func (m *Manager) AddFiltering(
	ip net.IP,
	port *fw.Port,
	direction fw.Direction,
	action fw.Action,
	comment string,
) (fw.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if port == nil || port.Values == nil || (port.IsRange && len(port.Values) != 2) {
		return nil, fmt.Errorf("invalid port definition")
	}
	pv := strconv.Itoa(port.Values[0])
	if port.IsRange {
		pv += ":" + strconv.Itoa(port.Values[1])
	}
	specs := m.filterRuleSpecs("filter", "INPUT", ip, pv, direction, action, comment)
	if err := m.client(ip).AppendUnique("filter", "INPUT", specs...); err != nil {
		return nil, err
	}
	m.ruleCnt++
	return &Rule{ruleNumber: m.ruleCnt, specs: specs, v6: ip.To4() == nil}, nil
}

// DeleteRule deletes a rule from the firewall
func (m *Manager) DeleteRule(rule fw.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}
	client := m.ipv4Client
	if r.v6 {
		client = m.ipv6Client
	}
	client.Delete("filter", chainFilterName, r.specs...)
	return nil
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	// clear chains from rules, if they doesn't exists create them
	if err := m.ipv4Client.ClearChain("filter", chainFilterName); err != nil {
		return err
	}
	if err := m.ipv6Client.ClearChain("filter", chainFilterName); err != nil {
		return err
	}
	return nil
}

// filterRuleSpecs returns the specs of a filtering rule and its id
//
// id builded by hashing the table, chain and specs together
func (m *Manager) filterRuleSpecs(
	table string, chain string, ip net.IP, port string,
	direction fw.Direction, action fw.Action, comment string,
) (specs []string) {
	if direction == fw.DirectionSrc {
		specs = append(specs, "-s", ip.String())
	}
	specs = append(specs, "-p", "tcp", "--dport", port)
	specs = append(specs, "-j", m.action(action))
	return append(specs, "-m", comment)
}

// client returns corresponding iptables client for the given ip
func (m *Manager) client(ip net.IP) *iptables.IPTables {
	if ip.To4() != nil {
		return m.ipv4Client
	}
	return m.ipv6Client
}

// action returns iptables action string for the given action
func (m *Manager) action(action fw.Action) string {
	if action == fw.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}
