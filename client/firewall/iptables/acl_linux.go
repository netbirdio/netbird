package iptables

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/nadoo/ipset"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	tableName = "filter"

	// rules chains contains the effective ACL rules
	chainNameInputRules  = "NETBIRD-ACL-INPUT"
	chainNameOutputRules = "NETBIRD-ACL-OUTPUT"
)

type aclManager struct {
	iptablesClient      *iptables.IPTables
	wgIface             iFaceMapper
	routeingFwChainName string

	entries   map[string][][]string
	ruleStore *rulesetStore
}

func newAclManager(iptablesClient *iptables.IPTables, wgIface iFaceMapper, routeingFwChainName string) (*aclManager, error) {
	m := &aclManager{
		iptablesClient:      iptablesClient,
		wgIface:             wgIface,
		routeingFwChainName: routeingFwChainName,

		entries:   make(map[string][][]string),
		ruleStore: newRulesetStore(),
	}

	err := ipset.Init()
	if err != nil {
		return nil, fmt.Errorf("faild to init ipset: %w", err)
	}

	m.seedInitialEntries()

	err = m.cleanChains()
	if err != nil {
		return nil, err
	}

	err = m.createDefaultChains()
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *aclManager) AddFiltering(
	ip net.IP,
	protocol firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
) ([]firewall.Rule, error) {
	var dPortVal, sPortVal string
	if dPort != nil && dPort.Values != nil {
		// TODO: we support only one port per rule in current implementation of ACLs
		dPortVal = strconv.Itoa(dPort.Values[0])
	}
	if sPort != nil && sPort.Values != nil {
		sPortVal = strconv.Itoa(sPort.Values[0])
	}
	ipsetName = transformIPsetName(ipsetName, sPortVal, dPortVal)

	ruleID := uuid.New().String()

	if ipsetName != "" {
		rs, rsExists := m.ruleStore.ruleset(ipsetName)
		if rsExists {
			if err := ipset.Add(ipsetName, ip.String()); err != nil {
				return nil, fmt.Errorf("failed to add IP to ipset: %w", err)
			}
			// if ruleset already exists it means we already have the firewall rule
			// so we need to update IPs in the ruleset and return new fw.Rule object for ACL manager.
			rs.addIP(ip.String())
			return []firewall.Rule{&Rule{
				ruleID:    ruleID,
				ipsetName: ipsetName,
				ip:        ip.String(),
				dst:       direction == firewall.RuleDirectionOUT,
			}}, nil
		}

		if err := ipset.Flush(ipsetName); err != nil {
			log.Errorf("flush ipset %q before use it: %v", ipsetName, err)
		}
		if err := ipset.Create(ipsetName); err != nil {
			return nil, fmt.Errorf("failed to create ipset: %w", err)
		}
		if err := ipset.Add(ipsetName, ip.String()); err != nil {
			return nil, fmt.Errorf("failed to add IP to ipset: %w", err)
		}
		// this is new ipset so we need to create firewall rule for it
	}

	specs := filterRuleSpecs(ip, string(protocol), sPortVal, dPortVal, direction, action, ipsetName)

	if direction == firewall.RuleDirectionOUT {
		ok, err := m.iptablesClient.Exists("filter", chainNameOutputRules, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is output rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := m.iptablesClient.Insert("filter", chainNameOutputRules, 1, specs...); err != nil {
			return nil, err
		}
	} else {
		ok, err := m.iptablesClient.Exists("filter", chainNameInputRules, specs...)
		if err != nil {
			return nil, fmt.Errorf("check is input rule already exists: %w", err)
		}
		if ok {
			return nil, fmt.Errorf("input rule already exists")
		}

		if err := m.iptablesClient.Insert("filter", chainNameInputRules, 1, specs...); err != nil {
			return nil, err
		}
	}

	rule := &Rule{
		ruleID:    ruleID,
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		dst:       direction == firewall.RuleDirectionOUT,
	}
	if ipsetName != "" {
		// ipset name is defined and it means that this rule was created
		// for it, need to associate it with ruleset
		m.ruleStore.newRuleset(ip.String())
	}

	return []firewall.Rule{rule}, nil
}

// DeleteRule from the firewall by rule definition
func (m *aclManager) DeleteRule(rule firewall.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	if rs, ok := m.ruleStore.ruleset(r.ipsetName); ok {
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
		m.ruleStore.deleteRuleset(r.ipsetName)

		if err := ipset.Destroy(r.ipsetName); err != nil {
			log.Errorf("delete empty ipset: %v", err)
		}
	}

	if r.dst {
		return m.iptablesClient.Delete("filter", chainNameOutputRules, r.specs...)
	}
	return m.iptablesClient.Delete("filter", chainNameInputRules, r.specs...)
}

func (m *aclManager) Reset() error {
	return m.cleanChains()
}

func (m *aclManager) cleanChains() error {
	ok, err := m.iptablesClient.ChainExists(tableName, chainNameOutputRules)
	if err != nil {
		log.Debugf("failed to list chains: %s", err)
		return err
	}
	if ok {
		rules := m.entries["OUTPUT"]
		for _, rule := range rules {
			err := m.iptablesClient.DeleteIfExists(tableName, "OUTPUT", rule...)
			if err != nil {
				log.Errorf("failed to delete rule: %v, %s", rule, err)
			}
		}

		err = m.iptablesClient.ClearAndDeleteChain(tableName, chainNameOutputRules)
		if err != nil {
			log.Debugf("failed to clear and delete %s chain: %s", chainNameOutputRules, err)
			return err
		}
	}

	ok, err = m.iptablesClient.ChainExists(tableName, chainNameInputRules)
	if err != nil {
		log.Debugf("failed to list chains: %s", err)
		return err
	}
	if ok {
		for _, rule := range m.entries["INPUT"] {
			err := m.iptablesClient.DeleteIfExists(tableName, "INPUT", rule...)
			if err != nil {
				log.Errorf("failed to delete rule: %v, %s", rule, err)
			}
		}

		for _, rule := range m.entries["FORWARD"] {
			err := m.iptablesClient.DeleteIfExists(tableName, "FORWARD", rule...)
			if err != nil {
				log.Errorf("failed to delete rule: %v, %s", rule, err)
			}
		}

		err = m.iptablesClient.ClearAndDeleteChain(tableName, chainNameInputRules)
		if err != nil {
			log.Debugf("failed to clear and delete %s chain: %s", chainNameInputRules, err)
			return err
		}
	}

	for _, ipsetName := range m.ruleStore.ipsetNames() {
		if err := ipset.Flush(ipsetName); err != nil {
			log.Errorf("flush ipset %q during reset: %v", ipsetName, err)
		}
		if err := ipset.Destroy(ipsetName); err != nil {
			log.Errorf("delete ipset %q during reset: %v", ipsetName, err)
		}
		m.ruleStore.deleteRuleset(ipsetName)
	}

	return nil
}

func (m *aclManager) createDefaultChains() error {
	// chain netbird-acl-input-rules
	if err := m.iptablesClient.NewChain(tableName, chainNameInputRules); err != nil {
		log.Errorf("failed to create '%s' chain: %s", chainNameInputRules, err)
		return err
	}

	// chain netbird-acl-output-rules
	if err := m.iptablesClient.NewChain(tableName, chainNameOutputRules); err != nil {
		log.Errorf("failed to create '%s' chain: %s", chainNameOutputRules, err)
		return err
	}

	for chainName, rules := range m.entries {
		for _, rule := range rules {
			if err := m.iptablesClient.AppendUnique(tableName, chainName, rule...); err != nil {
				log.Errorf("failed to create input chain jump rule: %s", err)
				return err
			}
		}
	}
	return nil
}

func (m *aclManager) seedInitialEntries() {
	m.appendToEntries("INPUT",
		[]string{"-i", m.wgIface.Name(), "!", "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("INPUT",
		[]string{"-i", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", chainNameInputRules})

	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("OUTPUT",
		[]string{"-o", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "!", "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("OUTPUT",
		[]string{"-o", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", chainNameOutputRules})

	m.appendToEntries("OUTPUT", []string{"-o", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", m.routeingFwChainName})
	m.appendToEntries("FORWARD", []string{"-o", m.wgIface.Name(), "-j", m.routeingFwChainName})
	m.appendToEntries("FORWARD",
		[]string{"-i", m.wgIface.Name(), "-m", "mark", "--mark", "0x000007e4", "-j", "ACCEPT"})
	m.appendToEntries("FORWARD",
		[]string{"-o", m.wgIface.Name(), "-m", "mark", "--mark", "0x000007e4", "-j", "ACCEPT"})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", chainNameInputRules})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("PREROUTING", []string{"-t", "mangle", "-i", m.wgIface.Name(), "!", "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().IP.String(), "-m", "mark", "--mark", "0x000007e4"})
}

func (m *aclManager) appendToEntries(chainName string, spec []string) {
	m.entries[chainName] = append(m.entries[chainName], spec)
}

// filterRuleSpecs returns the specs of a filtering rule
func filterRuleSpecs(
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
	return append(specs, "-j", actionToStr(action))
}

func actionToStr(action firewall.Action) string {
	if action == firewall.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}

func transformIPsetName(ipsetName string, sPort, dPort string) string {
	if ipsetName == "" {
		return ""
	} else if sPort != "" && dPort != "" {
		return ipsetName + "-sport-dport"
	} else if sPort != "" {
		return ipsetName + "-sport"
	} else if dPort != "" {
		return ipsetName + "-dport"
	}
	return ipsetName
}
