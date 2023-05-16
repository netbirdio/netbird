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
	// ChainInputFilterName is the name of the chain that is used for filtering incoming packets
	ChainInputFilterName = "NETBIRD-ACL-INPUT"

	// ChainOutputFilterName is the name of the chain that is used for filtering outgoing packets
	ChainOutputFilterName = "NETBIRD-ACL-OUTPUT"
)

// jumpNetbirdInputDefaultRule always added by manager to the input chain for all trafic from the Netbird interface
var jumpNetbirdInputDefaultRule = []string{"-j", ChainInputFilterName}

// jumpNetbirdOutputDefaultRule always added by manager to the output chain for all trafic from the Netbird interface
var jumpNetbirdOutputDefaultRule = []string{"-j", ChainOutputFilterName}

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
		log.Errorf("ip6tables is not installed in the system or not supported: %v", err)
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
	sPort *fw.Port,
	dPort *fw.Port,
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

	var dPortVal, sPortVal string
	if dPort != nil && dPort.Values != nil {
		// TODO: we support only one port per rule in current implementation of ACLs
		dPortVal = strconv.Itoa(dPort.Values[0])
	}
	if sPort != nil && sPort.Values != nil {
		sPortVal = strconv.Itoa(sPort.Values[0])
	}

	ruleID := uuid.New().String()
	if comment == "" {
		comment = ruleID
	}

	specs := m.filterRuleSpecs(
		"filter",
		ip,
		string(protocol),
		sPortVal,
		dPortVal,
		direction,
		action,
		comment,
	)

	if direction == fw.DirectionDst {
		ok, err := client.Exists("filter", ChainOutputFilterName, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is output rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := client.Insert("filter", ChainOutputFilterName, 1, specs...); err != nil {
			return nil, err
		}
	} else {
		ok, err := client.Exists("filter", ChainInputFilterName, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is input rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := client.Insert("filter", ChainInputFilterName, 1, specs...); err != nil {
			return nil, err
		}
	}

	return &Rule{
		id:    ruleID,
		specs: specs,
		dst:   direction == fw.DirectionDst,
		v6:    ip.To4() == nil,
	}, nil
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

	if r.dst {
		return client.Delete("filter", ChainOutputFilterName, r.specs...)
	}
	return client.Delete("filter", ChainInputFilterName, r.specs...)
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.reset(m.ipv4Client, "filter"); err != nil {
		return fmt.Errorf("clean ipv4 firewall ACL input chain: %w", err)
	}
	if m.ipv6Client != nil {
		if err := m.reset(m.ipv6Client, "filter"); err != nil {
			return fmt.Errorf("clean ipv6 firewall ACL input chain: %w", err)
		}
	}

	return nil
}

// reset firewall chain, clear it and drop it
func (m *Manager) reset(client *iptables.IPTables, table string) error {
	ok, err := client.ChainExists(table, ChainInputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if input chain exists: %w", err)
	}
	if ok {
		specs := append([]string{"-i", m.wgIfaceName}, jumpNetbirdInputDefaultRule...)
		if ok, err := client.Exists("filter", "INPUT", specs...); err != nil {
			return err
		} else if ok {
			if err := client.Delete("filter", "INPUT", specs...); err != nil {
				log.WithError(err).Errorf("failed to delete default input rule: %v", err)
			}
		}
	}

	ok, err = client.ChainExists(table, ChainOutputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if output chain exists: %w", err)
	}
	if ok {
		specs := append([]string{"-o", m.wgIfaceName}, jumpNetbirdOutputDefaultRule...)
		if ok, err := client.Exists("filter", "OUTPUT", specs...); err != nil {
			return err
		} else if ok {
			if err := client.Delete("filter", "OUTPUT", specs...); err != nil {
				log.WithError(err).Errorf("failed to delete default output rule: %v", err)
			}
		}
	}

	if err := client.ClearAndDeleteChain(table, ChainInputFilterName); err != nil {
		log.Errorf("failed to clear and delete input chain: %v", err)
		return nil
	}

	if err := client.ClearAndDeleteChain(table, ChainOutputFilterName); err != nil {
		log.Errorf("failed to clear and delete input chain: %v", err)
		return nil
	}

	return nil
}

// filterRuleSpecs returns the specs of a filtering rule
func (m *Manager) filterRuleSpecs(
	table string, ip net.IP, protocol string, sPort, dPort string,
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
	if sPort != "" {
		specs = append(specs, "--sport", sPort)
	}
	if dPort != "" {
		specs = append(specs, "--dport", dPort)
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

	ok, err := client.ChainExists("filter", ChainInputFilterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if chain exists: %w", err)
	}

	if !ok {
		if err := client.NewChain("filter", ChainInputFilterName); err != nil {
			return nil, fmt.Errorf("failed to create input chain: %w", err)
		}

		if err := client.AppendUnique("filter", ChainInputFilterName, pingSupportDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default input ping allow rule: %w", err)
		}

		if err := client.AppendUnique("filter", ChainInputFilterName, dropAllDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default drop all in netbird input chain: %w", err)
		}

		specs := append([]string{"-i", m.wgIfaceName}, jumpNetbirdInputDefaultRule...)
		if err := client.AppendUnique("filter", "INPUT", specs...); err != nil {
			return nil, fmt.Errorf("failed to create input chain jump rule: %w", err)
		}

	}

	ok, err = client.ChainExists("filter", ChainOutputFilterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if chain exists: %w", err)
	}

	if !ok {
		if err := client.NewChain("filter", ChainOutputFilterName); err != nil {
			return nil, fmt.Errorf("failed to create output chain: %w", err)
		}

		if err := client.AppendUnique("filter", ChainOutputFilterName, pingSupportDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default output ping allow rule: %w", err)
		}

		if err := client.AppendUnique("filter", ChainOutputFilterName, dropAllDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default drop all in netbird output chain: %w", err)
		}

		specs := append([]string{"-o", m.wgIfaceName}, jumpNetbirdOutputDefaultRule...)
		if err := client.AppendUnique("filter", "OUTPUT", specs...); err != nil {
			return nil, fmt.Errorf("failed to create output chain jump rule: %w", err)
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
