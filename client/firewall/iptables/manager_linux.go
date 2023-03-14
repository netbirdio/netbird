package iptables

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"

	fw "github.com/netbirdio/netbird/client/firewall"
)

const (
	// ChainFilterName is the name of the chain that is used for filtering by the Netbird client
	ChainFilterName = "NETBIRD-ACL"
)

// Manager of iptables firewall
type Manager struct {
<<<<<<< HEAD
	mutex sync.Mutex

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

// AddFiltering rule to the firewall
func (m *Manager) AddFiltering(
	ip net.IP,
	port *fw.Port,
	direction fw.Direction,
	action fw.Action,
	comment string,
) (fw.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	client := m.client(ip)
	ok, err := client.ChainExists("filter", ChainFilterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if chain exists: %s", err)
	}
	if !ok {
		if err := client.NewChain("filter", ChainFilterName); err != nil {
			return nil, fmt.Errorf("failed to create chain: %s", err)
		}
	}
	if port == nil || port.Values == nil || (port.IsRange && len(port.Values) != 2) {
		return nil, fmt.Errorf("invalid port definition")
	}
	pv := strconv.Itoa(port.Values[0])
	if port.IsRange {
		pv += ":" + strconv.Itoa(port.Values[1])
	}
	specs := m.filterRuleSpecs("filter", ChainFilterName, ip, pv, direction, action, comment)
	if err := client.AppendUnique("filter", ChainFilterName, specs...); err != nil {
		return nil, err
	}
	rule := &Rule{
		id:    uuid.New().String(),
		specs: specs,
		v6:    ip.To4() == nil,
	}
	return rule, nil
}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule fw.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}
	client := m.ipv4Client
	if r.v6 {
		client = m.ipv6Client
	}
	return client.Delete("filter", ChainFilterName, r.specs...)
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.reset(m.ipv4Client, "filter", ChainFilterName); err != nil {
		return fmt.Errorf("clean ipv4 firewall ACL chain: %w", err)
	}
	if err := m.reset(m.ipv6Client, "filter", ChainFilterName); err != nil {
		return fmt.Errorf("clean ipv6 firewall ACL chain: %w", err)
	}
	return nil
}

// reset firewall chain, clear it and drop it
func (m *Manager) reset(client *iptables.IPTables, table, chain string) error {
	ok, err := client.ChainExists(table, chain)
	if err != nil {
		return fmt.Errorf("failed to check if chain exists: %w", err)
	}
	if !ok {
		return nil
	}
	if err := client.ClearChain(table, ChainFilterName); err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}
	return client.DeleteChain(table, ChainFilterName)
}

// filterRuleSpecs returns the specs of a filtering rule
func (m *Manager) filterRuleSpecs(
	table string, chain string, ip net.IP, port string,
	direction fw.Direction, action fw.Action, comment string,
) (specs []string) {
	if direction == fw.DirectionSrc {
		specs = append(specs, "-s", ip.String())
	}
	specs = append(specs, "-p", "tcp", "--dport", port)
	specs = append(specs, "-j", m.actionToStr(action))
	return append(specs, "-m", "comment", "--comment", comment)
}

// client returns corresponding iptables client for the given ip
func (m *Manager) client(ip net.IP) *iptables.IPTables {
	if ip.To4() != nil {
		return m.ipv4Client
	}
	return m.ipv6Client
}

func (m *Manager) actionToStr(action fw.Action) string {
	if action == fw.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}
