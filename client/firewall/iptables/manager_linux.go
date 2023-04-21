package iptables

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"

	fw "github.com/netbirdio/netbird/client/firewall"
	log "github.com/sirupsen/logrus"
)

const (
	// ChainFilterName is the name of the chain that is used for filtering by the Netbird client
	ChainFilterName = "NETBIRD-ACL"
)

// jumpNetbirdDefaultRule always added by manager to the input chain for all trafic from the Netbird interface
var jumpNetbirdDefaultRule = []string{
	"-j", ChainFilterName, "-m", "comment", "--comment", "Netbird traffic chain jump"}

// pingSupportDefaultRule always added by the manager to the Netbird ACL chain
var pingSupportDefaultRule = []string{
	"-p", "icmp", "--icmp-type", "echo-request", "-j",
	"ACCEPT", "-m", "comment", "--comment", "Allow pings from the Netbird Devices"}

// dropAllDefaultRule in the Netbird chain
var dropAllDefaultRule = []string{"-j", "DROP"}

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables

	wgIfaceName string
}

// Create iptables firewall manager
func Create(wgIfaceName string) (*Manager, error) {
	m := &Manager{
		wgIfaceName: wgIfaceName,
	}

	// init clients for booth ipv4 and ipv6
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not supported")
	}
	m.ipv4Client = ipv4Client

	ipv6Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("ip6tables is not installed in the system or not supported")
	} else {
		m.ipv6Client = ipv6Client
	}

	if err := m.Reset(); err != nil {
		return nil, fmt.Errorf("failed to reset firewall: %v", err)
	}
	return m, nil
}

// AddFiltering rule to the firewall
//
// If comment is empty rule ID is used as comment
func (m *Manager) AddFiltering(
	ip net.IP,
	protocol fw.Protocol,
	port *fw.Port,
	direction fw.Direction,
	action fw.Action,
	comment string,
) (fw.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	client, err := m.client(ip)
	if err != nil {
		return nil, err
	}

	var portValue string
	if port != nil && port.Values != nil {
		// TODO: we support only one port per rule in current implementation of ACLs
		portValue = strconv.Itoa(port.Values[0])
	}

	ruleID := uuid.New().String()
	if comment == "" {
		comment = ruleID
	}

	specs := m.filterRuleSpecs(
		"filter",
		ChainFilterName,
		ip,
		string(protocol),
		portValue,
		direction,
		action,
		comment,
	)

	ok, err := client.Exists("filter", ChainFilterName, specs...)
	if err != nil {
		return nil, fmt.Errorf("check is rule already exists: %w", err)
	}
	if ok {
		return nil, fmt.Errorf("rule already exists")
	}

	if err := client.Insert("filter", ChainFilterName, 1, specs...); err != nil {
		return nil, err
	}

	return &Rule{id: ruleID, specs: specs, v6: ip.To4() == nil}, nil
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
		if m.ipv6Client == nil {
			return fmt.Errorf("ipv6 is not supported")
		}
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
	if m.ipv6Client != nil {
		if err := m.reset(m.ipv6Client, "filter", ChainFilterName); err != nil {
			return fmt.Errorf("clean ipv6 firewall ACL chain: %w", err)
		}
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

	specs := append([]string{"-i", m.wgIfaceName}, jumpNetbirdDefaultRule...)
	if err := client.Delete("filter", "INPUT", specs...); err != nil {
		return fmt.Errorf("failed to delete default rule: %w", err)
	}

	return client.ClearAndDeleteChain(table, chain)
}

// filterRuleSpecs returns the specs of a filtering rule
func (m *Manager) filterRuleSpecs(
	table string, chain string, ip net.IP, protocol string, port string,
	direction fw.Direction, action fw.Action, comment string,
) (specs []string) {
	switch direction {
	case fw.DirectionSrc:
		specs = append(specs, "-s", ip.String())
	case fw.DirectionDst:
		specs = append(specs, "-d", ip.String())
	}
	if protocol != "all" {
		specs = append(specs, "-p", protocol)
	}
	if port != "" {
		specs = append(specs, "--dport", port)
	}
	specs = append(specs, "-j", m.actionToStr(action))
	return append(specs, "-m", "comment", "--comment", comment)
}

// rawClient returns corresponding iptables client for the given ip
func (m *Manager) rawClient(ip net.IP) (*iptables.IPTables, error) {
	if ip.To4() != nil {
		return m.ipv4Client, nil
	}
	if m.ipv6Client == nil {
		return nil, fmt.Errorf("ipv6 is not supported")
	}
	return m.ipv6Client, nil
}

// client returns client with initialized chain and default rules
func (m *Manager) client(ip net.IP) (*iptables.IPTables, error) {
	client, err := m.rawClient(ip)
	if err != nil {
		return nil, err
	}

	ok, err := client.ChainExists("filter", ChainFilterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if chain exists: %w", err)
	}

	if !ok {
		if err := client.NewChain("filter", ChainFilterName); err != nil {
			return nil, fmt.Errorf("failed to create chain: %w", err)
		}

		if err := client.AppendUnique("filter", ChainFilterName, pingSupportDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default ping allow rule: %w", err)
		}

		if err := client.AppendUnique("filter", ChainFilterName, dropAllDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default drop all in netbird chain: %w", err)
		}

		specs := append([]string{"-i", m.wgIfaceName}, jumpNetbirdDefaultRule...)
		if err := client.AppendUnique("filter", "INPUT", specs...); err != nil {
			return nil, fmt.Errorf("failed to create chain: %w", err)
		}

	}
	return client, nil
}

func (m *Manager) actionToStr(action fw.Action) string {
	if action == fw.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}
