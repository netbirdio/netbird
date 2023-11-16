package iptables

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/nadoo/ipset"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
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

	inputDefaultRuleSpecs  []string
	outputDefaultRuleSpecs []string
	wgIface                iFaceMapper

	rulesets map[string]ruleset
	router   *routerManager
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
func Create(context context.Context, wgIface iFaceMapper) (*Manager, error) {
	err := ipset.Init()
	if err != nil {
		return nil, fmt.Errorf("init ipset: %w", err)
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not supported")
	}

	m := &Manager{
		wgIface: wgIface,
		inputDefaultRuleSpecs: []string{
			"-i", wgIface.Name(), "-j", ChainInputFilterName, "-s", wgIface.Address().String()},
		outputDefaultRuleSpecs: []string{
			"-o", wgIface.Name(), "-j", ChainOutputFilterName, "-d", wgIface.Address().String()},
		rulesets: make(map[string]ruleset),
		router:   newRouterManager(context, iptablesClient),
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
	protocol firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
	comment string,
) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	err := m.initialize()
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
				dst:       direction == firewall.RuleDirectionOUT,
				v6:        ip.To4() == nil,
			}, nil
		}
		// this is new ipset so we need to create firewall rule for it
	}

	specs := m.filterRuleSpecs(ip, string(protocol), sPortVal, dPortVal, direction, action, ipsetName)

	if direction == firewall.RuleDirectionOUT {
		ok, err := m.ipv4Client.Exists("filter", ChainOutputFilterName, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is output rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := m.ipv4Client.Insert("filter", ChainOutputFilterName, 1, specs...); err != nil {
			return nil, err
		}
	} else {
		ok, err := m.ipv4Client.Exists("filter", ChainInputFilterName, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is input rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := m.ipv4Client.Insert("filter", ChainInputFilterName, 1, specs...); err != nil {
			return nil, err
		}
	}

	rule := &Rule{
		ruleID:    ruleID,
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		dst:       direction == firewall.RuleDirectionOUT,
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
func (m *Manager) DeleteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
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
		return m.ipv4Client.Delete("filter", ChainOutputFilterName, r.specs...)
	}
	return m.ipv4Client.Delete("filter", ChainInputFilterName, r.specs...)
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) InsertRoutingRules(pair firewall.RouterPair) error {
	return m.router.InsertRoutingRules(pair)
}

func (m *Manager) RemoveRoutingRules(pair firewall.RouterPair) error {
	return m.router.RemoveRoutingRules(pair)
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.resetFilter(); err != nil {
		return fmt.Errorf("clean firewall ACL input chain: %w", err)
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
			firewall.RuleDirectionIN,
			firewall.ActionAccept,
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
			firewall.RuleDirectionOUT,
			firewall.ActionAccept,
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
func (m *Manager) resetFilter() error {
	ok, err := m.ipv4Client.ChainExists("filter", ChainInputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if input chain exists: %w", err)
	}
	if ok {
		if ok, err := m.ipv4Client.Exists("filter", "INPUT", m.inputDefaultRuleSpecs...); err != nil {
			return err
		} else if ok {
			if err := m.ipv4Client.Delete("filter", "INPUT", m.inputDefaultRuleSpecs...); err != nil {
				log.WithError(err).Errorf("failed to delete default input rule: %v", err)
			}
		}
	}

	ok, err = m.ipv4Client.ChainExists("filter", ChainOutputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if output chain exists: %w", err)
	}
	if ok {
		if ok, err := m.ipv4Client.Exists("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
			return err
		} else if ok {
			if err := m.ipv4Client.Delete("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
				log.WithError(err).Errorf("failed to delete default output rule: %v", err)
			}
		}
	}

	if err := m.ipv4Client.ClearAndDeleteChain("filter", ChainInputFilterName); err != nil {
		log.Errorf("failed to clear and delete input chain: %v", err)
		return nil
	}

	if err := m.ipv4Client.ClearAndDeleteChain("filter", ChainOutputFilterName); err != nil {
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
	ip net.IP, protocol string, sPort, dPort string, direction firewall.RuleDirection, action firewall.Action, ipsetName string,
) (specs []string) {
	matchByIP := true
	// don't use IP matching if IP is ip 0.0.0.0
	if s := ip.String(); s == "0.0.0.0" || s == "::" {
		matchByIP = false
	}
	switch direction {
	case firewall.RuleDirectionIN:
		if matchByIP {
			if ipsetName != "" {
				specs = append(specs, "-m", "set", "--set", ipsetName, "src")
			} else {
				specs = append(specs, "-s", ip.String())
			}
		}
	case firewall.RuleDirectionOUT:
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

// initialize chain and default rules
func (m *Manager) initialize() error {
	ok, err := m.ipv4Client.ChainExists("filter", ChainInputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if chain exists: %w", err)
	}

	if !ok {
		if err := m.ipv4Client.NewChain("filter", ChainInputFilterName); err != nil {
			return fmt.Errorf("failed to create input chain: %w", err)
		}

		if err := m.ipv4Client.AppendUnique("filter", ChainInputFilterName, dropAllDefaultRule...); err != nil {
			return fmt.Errorf("failed to create default drop all in netbird input chain: %w", err)
		}

		if err := m.ipv4Client.Insert("filter", "INPUT", 1, m.inputDefaultRuleSpecs...); err != nil {
			return fmt.Errorf("failed to create input chain jump rule: %w", err)
		}

	}

	ok, err = m.ipv4Client.ChainExists("filter", ChainOutputFilterName)
	if err != nil {
		return fmt.Errorf("failed to check if chain exists: %w", err)
	}
	if ok {
		return nil
	}

	if err := m.ipv4Client.NewChain("filter", ChainOutputFilterName); err != nil {
		return fmt.Errorf("failed to create output chain: %w", err)
	}

	if err := m.ipv4Client.AppendUnique("filter", ChainOutputFilterName, dropAllDefaultRule...); err != nil {
		return fmt.Errorf("failed to create default drop all in netbird output chain: %w", err)
	}

	if err := m.ipv4Client.AppendUnique("filter", "OUTPUT", m.outputDefaultRuleSpecs...); err != nil {
		return fmt.Errorf("failed to create output chain jump rule: %w", err)
	}
	return nil
}

func (m *Manager) actionToStr(action firewall.Action) string {
	if action == firewall.ActionAccept {
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
