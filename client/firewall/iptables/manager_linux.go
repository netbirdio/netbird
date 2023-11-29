package iptables

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/nadoo/ipset"
	log "github.com/sirupsen/logrus"

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

const (
	// ChainInputFilterName is the name of the chain that is used for filtering incoming packets
	ChainInputFilterName = "NETBIRD-ACL-INPUT"

	// ChainOutputFilterName is the name of the chain that is used for filtering outgoing packets
	ChainOutputFilterName = "NETBIRD-ACL-OUTPUT"
)

// dropAllDefaultRule in the Netbird chain
var dropAllDefaultRule = []string{"-j", "DROP"}

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables

	inputDefaultRuleSpecs  []string
	outputDefaultRuleSpecs []string
	wgIface                iFaceMapper

	rulesets map[string]ruleset
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
}

type ruleset struct {
	rule *Rule
	ips  map[string]string
}

// Create iptables firewall manager
func Create(wgIface iFaceMapper, ipv6Supported bool) (*Manager, error) {
	m := &Manager{
		wgIface: wgIface,
		inputDefaultRuleSpecs: []string{
			"-i", wgIface.Name(), "-j", ChainInputFilterName, "-s", wgIface.Address().String()},
		outputDefaultRuleSpecs: []string{
			"-o", wgIface.Name(), "-j", ChainOutputFilterName, "-d", wgIface.Address().String()},
		rulesets: make(map[string]ruleset),
	}

	err := ipset.Init()
	if err != nil {
		return nil, fmt.Errorf("init ipset: %w", err)
	}

	// init clients for booth ipv4 and ipv6
	m.ipv4Client, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not supported")
	}

	if ipv6Supported {
		m.ipv6Client, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			log.Warnf("ip6tables is not installed in the system or not supported: %v. Access rules for this protocol won't be applied.", err)
		}
	}

	if m.ipv4Client == nil && m.ipv6Client == nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not enough permissions to use it")
	}

	if err := m.Reset(); err != nil {
		return nil, fmt.Errorf("failed to reset firewall: %v", err)
	}
	return m, nil
}

// AddFiltering rule to the firewall
//
// Comment will be ignored because some system this feature is not supported
func (m *Manager) AddFiltering(
	ip net.IP,
	protocol fw.Protocol,
	sPort *fw.Port,
	dPort *fw.Port,
	direction fw.RuleDirection,
	action fw.Action,
	ipsetName string,
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
	ipsetName = m.transformIPsetName(ipsetName, sPortVal, dPortVal)

	ruleID := uuid.New().String()

	if ipsetName != "" {
		rs, rsExists := m.rulesets[ipsetName]
		if !rsExists {
			if err := ipset.Flush(ipsetName); err != nil {
				log.Errorf("flush ipset %q before use it: %v", ipsetName, err)
			}
			if err := ipset.Create(ipsetName); err != nil {
				return nil, fmt.Errorf("failed to create ipset: %w", err)
			}
		}

		if err := ipset.Add(ipsetName, ip.String()); err != nil {
			return nil, fmt.Errorf("failed to add IP to ipset: %w", err)
		}

		if rsExists {
			// if ruleset already exists it means we already have the firewall rule
			// so we need to update IPs in the ruleset and return new fw.Rule object for ACL manager.
			rs.ips[ip.String()] = ruleID
			return &Rule{
				ruleID:    ruleID,
				ipsetName: ipsetName,
				ip:        ip.String(),
				dst:       direction == fw.RuleDirectionOUT,
				v6:        ip.To4() == nil,
			}, nil
		}
		// this is new ipset so we need to create firewall rule for it
	}

	specs := m.filterRuleSpecs(ip, string(protocol), sPortVal, dPortVal, direction, action, ipsetName)

	if direction == fw.RuleDirectionOUT {
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

	rule := &Rule{
		ruleID:    ruleID,
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		dst:       direction == fw.RuleDirectionOUT,
		v6:        ip.To4() == nil,
	}
	if ipsetName != "" {
		// ipset name is defined and it means that this rule was created
		// for it, need to associate it with ruleset
		m.rulesets[ipsetName] = ruleset{
			rule: rule,
			ips:  map[string]string{rule.ip: ruleID},
		}
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
		if m.ipv6Client == nil {
			return fmt.Errorf("ipv6 is not supported")
		}
		client = m.ipv6Client
	}

	if rs, ok := m.rulesets[r.ipsetName]; ok {
		// delete IP from ruleset IPs list and ipset
		if _, ok := rs.ips[r.ip]; ok {
			if err := ipset.Del(r.ipsetName, r.ip); err != nil {
				return fmt.Errorf("failed to delete ip from ipset: %w", err)
			}
			delete(rs.ips, r.ip)
		}

		// if after delete, set still contains other IPs,
		// no need to delete firewall rule and we should exit here
		if len(rs.ips) != 0 {
			return nil
		}

		// we delete last IP from the set, that means we need to delete
		// set itself and associated firewall rule too
		delete(m.rulesets, r.ipsetName)

		if err := ipset.Destroy(r.ipsetName); err != nil {
			log.Errorf("delete empty ipset: %v", err)
		}
		r = rs.rule
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

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if m.wgIface.IsUserspaceBind() {
		_, err := m.AddFiltering(
			net.ParseIP("0.0.0.0"),
			"all",
			nil,
			nil,
			fw.RuleDirectionIN,
			fw.ActionAccept,
			"",
			"",
		)
		if err != nil {
			return fmt.Errorf("failed to allow netbird interface traffic: %w", err)
		}
		_, err = m.AddFiltering(
			net.ParseIP("0.0.0.0"),
			"all",
			nil,
			nil,
			fw.RuleDirectionOUT,
			fw.ActionAccept,
			"",
			"",
		)
		return err
	}

	return nil
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

// reset firewall chain, clear it and drop it
func (m *Manager) reset(client *iptables.IPTables, table string) error {
	ok, err := client.ChainExists(table, ChainInputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if input chain exists: %w", err)
	}
	if ok {
		if ok, err := client.Exists("filter", "INPUT", m.inputDefaultRuleSpecs...); err != nil {
			return err
		} else if ok {
			if err := client.Delete("filter", "INPUT", m.inputDefaultRuleSpecs...); err != nil {
				log.WithError(err).Errorf("failed to delete default input rule: %v", err)
			}
		}
	}

	ok, err = client.ChainExists(table, ChainOutputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if output chain exists: %w", err)
	}
	if ok {
		if ok, err := client.Exists("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
			return err
		} else if ok {
			if err := client.Delete("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
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

	for ipsetName := range m.rulesets {
		if err := ipset.Flush(ipsetName); err != nil {
			log.Errorf("flush ipset %q during reset: %v", ipsetName, err)
		}
		if err := ipset.Destroy(ipsetName); err != nil {
			log.Errorf("delete ipset %q during reset: %v", ipsetName, err)
		}
		delete(m.rulesets, ipsetName)
	}

	return nil
}

// filterRuleSpecs returns the specs of a filtering rule
func (m *Manager) filterRuleSpecs(
	ip net.IP, protocol string, sPort, dPort string, direction fw.RuleDirection, action fw.Action, ipsetName string,
) (specs []string) {
	matchByIP := true
	// don't use IP matching if IP is ip 0.0.0.0
	if s := ip.String(); s == "0.0.0.0" || s == "::" {
		matchByIP = false
	}
	switch direction {
	case fw.RuleDirectionIN:
		if matchByIP {
			if ipsetName != "" {
				specs = append(specs, "-m", "set", "--set", ipsetName, "src")
			} else {
				specs = append(specs, "-s", ip.String())
			}
		}
	case fw.RuleDirectionOUT:
		if matchByIP {
			if ipsetName != "" {
				specs = append(specs, "-m", "set", "--set", ipsetName, "dst")
			} else {
				specs = append(specs, "-d", ip.String())
			}
		}
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
	return append(specs, "-j", m.actionToStr(action))
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

		if err := client.AppendUnique("filter", ChainInputFilterName, dropAllDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default drop all in netbird input chain: %w", err)
		}

		if err := client.Insert("filter", "INPUT", 1, m.inputDefaultRuleSpecs...); err != nil {
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

		if err := client.AppendUnique("filter", ChainOutputFilterName, dropAllDefaultRule...); err != nil {
			return nil, fmt.Errorf("failed to create default drop all in netbird output chain: %w", err)
		}

		if err := client.AppendUnique("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
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

func (m *Manager) transformIPsetName(ipsetName string, sPort, dPort string) string {
	switch {
	case ipsetName == "":
		return ""
	case sPort != "" && dPort != "":
		return ipsetName + "-sport-dport"
	case sPort != "":
		return ipsetName + "-sport"
	case dPort != "":
		return ipsetName + "-dport"
	default:
		return ipsetName
	}
}
