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

	postRoutingMark = "0x000007e4"
)

type aclManager struct {
	iptablesClient      *iptables.IPTables
	wgIface             iFaceMapper
	routeingFwChainName string

	entries    map[string][][]string
	ipsetStore *ipsetStore
}

func newAclManager(iptablesClient *iptables.IPTables, wgIface iFaceMapper, routeingFwChainName string) (*aclManager, error) {
	m := &aclManager{
		iptablesClient:      iptablesClient,
		wgIface:             wgIface,
		routeingFwChainName: routeingFwChainName,

		entries:    make(map[string][][]string),
		ipsetStore: newIpsetStore(),
	}

	err := ipset.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to init ipset: %w", err)
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

	var chain string
	if direction == firewall.RuleDirectionOUT {
		chain = chainNameOutputRules
	} else {
		chain = chainNameInputRules
	}

	ipsetName = transformIPsetName(ipsetName, sPortVal, dPortVal)
	specs := filterRuleSpecs(ip, string(protocol), sPortVal, dPortVal, direction, action, ipsetName)
	if ipsetName != "" {
		if ipList, ipsetExists := m.ipsetStore.ipset(ipsetName); ipsetExists {
			if err := ipset.Add(ipsetName, ip.String()); err != nil {
				return nil, fmt.Errorf("failed to add IP to ipset: %w", err)
			}
			// if ruleset already exists it means we already have the firewall rule
			// so we need to update IPs in the ruleset and return new fw.Rule object for ACL manager.
			ipList.addIP(ip.String())
			return []firewall.Rule{&Rule{
				ruleID:    uuid.New().String(),
				ipsetName: ipsetName,
				ip:        ip.String(),
				chain:     chain,
				specs:     specs,
			}}, nil
		}

		if err := ipset.Flush(ipsetName); err != nil {
			log.Errorf("flush ipset %s before use it: %s", ipsetName, err)
		}
		if err := ipset.Create(ipsetName); err != nil {
			return nil, fmt.Errorf("failed to create ipset: %w", err)
		}
		if err := ipset.Add(ipsetName, ip.String()); err != nil {
			return nil, fmt.Errorf("failed to add IP to ipset: %w", err)
		}

		ipList := newIpList(ip.String())
		m.ipsetStore.addIpList(ipsetName, ipList)
	}

	ok, err := m.iptablesClient.Exists("filter", chain, specs...)
	if err != nil {
		return nil, fmt.Errorf("failed to check rule: %w", err)
	}
	if ok {
		return nil, fmt.Errorf("rule already exists")
	}

	if err := m.iptablesClient.Insert("filter", chain, 1, specs...); err != nil {
		return nil, err
	}

	rule := &Rule{
		ruleID:    uuid.New().String(),
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		chain:     chain,
	}

	if !shouldAddToPrerouting(protocol, dPort, direction) {
		return []firewall.Rule{rule}, nil
	}

	rulePrerouting, err := m.addPreroutingFilter(ipsetName, string(protocol), dPortVal, ip)
	if err != nil {
		return []firewall.Rule{rule}, err
	}
	return []firewall.Rule{rule, rulePrerouting}, nil
}

// DeleteRule from the firewall by rule definition
func (m *aclManager) DeleteRule(rule firewall.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	if r.chain == "PREROUTING" {
		goto DELETERULE
	}

	if ipsetList, ok := m.ipsetStore.ipset(r.ipsetName); ok {
		// delete IP from ruleset IPs list and ipset
		if _, ok := ipsetList.ips[r.ip]; ok {
			if err := ipset.Del(r.ipsetName, r.ip); err != nil {
				return fmt.Errorf("failed to delete ip from ipset: %w", err)
			}
			delete(ipsetList.ips, r.ip)
		}

		// if after delete, set still contains other IPs,
		// no need to delete firewall rule and we should exit here
		if len(ipsetList.ips) != 0 {
			return nil
		}

		// we delete last IP from the set, that means we need to delete
		// set itself and associated firewall rule too
		m.ipsetStore.deleteIpset(r.ipsetName)

		if err := ipset.Destroy(r.ipsetName); err != nil {
			log.Errorf("delete empty ipset: %v", err)
		}
	}

DELETERULE:
	var table string
	if r.chain == "PREROUTING" {
		table = "mangle"
	} else {
		table = "filter"
	}
	err := m.iptablesClient.Delete(table, r.chain, r.specs...)
	if err != nil {
		log.Debugf("failed to delete rule, %s, %v: %s", r.chain, r.specs, err)
	}
	return err
}

func (m *aclManager) Reset() error {
	return m.cleanChains()
}

func (m *aclManager) addPreroutingFilter(ipsetName string, protocol string, port string, ip net.IP) (*Rule, error) {
	var src []string
	if ipsetName != "" {
		src = []string{"-m", "set", "--set", ipsetName, "src"}
	} else {
		src = []string{"-s", ip.String()}
	}
	specs := []string{
		"-d", m.wgIface.Address().IP.String(),
		"-p", protocol,
		"--dport", port,
		"-j", "MARK", "--set-mark", postRoutingMark,
	}

	specs = append(src, specs...)

	ok, err := m.iptablesClient.Exists("mangle", "PREROUTING", specs...)
	if err != nil {
		return nil, fmt.Errorf("failed to check rule: %w", err)
	}
	if ok {
		return nil, fmt.Errorf("rule already exists")
	}

	if err := m.iptablesClient.Insert("mangle", "PREROUTING", 1, specs...); err != nil {
		return nil, err
	}

	rule := &Rule{
		ruleID:    uuid.New().String(),
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		chain:     "PREROUTING",
	}
	return rule, nil
}

// todo write less destructive cleanup mechanism
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

	ok, err = m.iptablesClient.ChainExists("mangle", "PREROUTING")
	if err != nil {
		log.Debugf("failed to list chains: %s", err)
		return err
	}
	if ok {
		for _, rule := range m.entries["PREROUTING"] {
			err := m.iptablesClient.DeleteIfExists("mangle", "PREROUTING", rule...)
			if err != nil {
				log.Errorf("failed to delete rule: %v, %s", rule, err)
			}
		}
		err = m.iptablesClient.ClearChain("mangle", "PREROUTING")
		if err != nil {
			log.Debugf("failed to clear %s chain: %s", "PREROUTING", err)
			return err
		}
	}

	for _, ipsetName := range m.ipsetStore.ipsetNames() {
		if err := ipset.Flush(ipsetName); err != nil {
			log.Errorf("flush ipset %q during reset: %v", ipsetName, err)
		}
		if err := ipset.Destroy(ipsetName); err != nil {
			log.Errorf("delete ipset %q during reset: %v", ipsetName, err)
		}
		m.ipsetStore.deleteIpset(ipsetName)
	}

	return nil
}

func (m *aclManager) createDefaultChains() error {
	// chain netbird-acl-input-rules
	if err := m.iptablesClient.NewChain(tableName, chainNameInputRules); err != nil {
		log.Debugf("failed to create '%s' chain: %s", chainNameInputRules, err)
		return err
	}

	// chain netbird-acl-output-rules
	if err := m.iptablesClient.NewChain(tableName, chainNameOutputRules); err != nil {
		log.Debugf("failed to create '%s' chain: %s", chainNameOutputRules, err)
		return err
	}

	for chainName, rules := range m.entries {
		for _, rule := range rules {
			if chainName == "FORWARD" {
				// position 2 because we add it after router's, jump rule
				if err := m.iptablesClient.InsertUnique(tableName, "FORWARD", 2, rule...); err != nil {
					log.Debugf("failed to create input chain jump rule: %s", err)
					return err
				}
			} else {
				if err := m.iptablesClient.AppendUnique(tableName, chainName, rule...); err != nil {
					log.Debugf("failed to create input chain jump rule: %s", err)
					return err
				}
			}
		}
	}

	return nil
}

func (m *aclManager) seedInitialEntries() {
	m.appendToEntries("INPUT",
		[]string{"-i", m.wgIface.Name(), "!", "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("INPUT",
		[]string{"-i", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "!", "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("INPUT",
		[]string{"-i", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", chainNameInputRules})

	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("OUTPUT",
		[]string{"-o", m.wgIface.Name(), "!", "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("OUTPUT",
		[]string{"-o", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "!", "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})

	m.appendToEntries("OUTPUT",
		[]string{"-o", m.wgIface.Name(), "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().String(), "-j", chainNameOutputRules})

	m.appendToEntries("OUTPUT", []string{"-o", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", chainNameInputRules})
	m.appendToEntries("FORWARD",
		[]string{"-o", m.wgIface.Name(), "-m", "mark", "--mark", postRoutingMark, "-j", "ACCEPT"})
	m.appendToEntries("FORWARD",
		[]string{"-i", m.wgIface.Name(), "-m", "mark", "--mark", postRoutingMark, "-j", "ACCEPT"})
	m.appendToEntries("FORWARD", []string{"-o", m.wgIface.Name(), "-j", m.routeingFwChainName})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", m.routeingFwChainName})

	m.appendToEntries("PREROUTING",
		[]string{"-t", "mangle", "-i", m.wgIface.Name(), "!", "-s", m.wgIface.Address().String(), "-d", m.wgIface.Address().IP.String(), "-m", "mark", "--mark", postRoutingMark})
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
	if ip.String() == "0.0.0.0" {
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

func shouldAddToPrerouting(proto firewall.Protocol, dPort *firewall.Port, direction firewall.RuleDirection) bool {
	if proto == "all" {
		return false
	}

	if direction != firewall.RuleDirectionIN {
		return false
	}

	if dPort == nil {
		return false
	}
	return true
}
