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
	iptablesClient     *iptables.IPTables
	wgIface            iFaceMapper
	routingFwChainName string

	entries    map[string][][]string
	ipsetStore *ipsetStore
}

func newAclManager(iptablesClient *iptables.IPTables, wgIface iFaceMapper, routingFwChainName string) (*aclManager, error) {
	m := &aclManager{
		iptablesClient:     iptablesClient,
		wgIface:            wgIface,
		routingFwChainName: routingFwChainName,

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

func (m *aclManager) AddPeerFiltering(
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

	if err := m.iptablesClient.Append("filter", chain, specs...); err != nil {
		return nil, err
	}

	rule := &Rule{
		ruleID:    uuid.New().String(),
		specs:     specs,
		ipsetName: ipsetName,
		ip:        ip.String(),
		chain:     chain,
	}

	return []firewall.Rule{rule}, nil
}

// DeletePeerRule from the firewall by rule definition
func (m *aclManager) DeletePeerRule(rule firewall.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
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

	err := m.iptablesClient.Delete(tableName, r.chain, r.specs...)
	if err != nil {
		log.Debugf("failed to delete rule, %s, %v: %s", r.chain, r.specs, err)
	}
	return err
}

func (m *aclManager) Reset() error {
	return m.cleanChains()
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
			if err := m.iptablesClient.InsertUnique(tableName, chainName, 1, rule...); err != nil {
				log.Debugf("failed to create input chain jump rule: %s", err)
				return err
			}
		}
	}

	return nil
}

// seedInitialEntries adds default rules to the entries map, rules are inserted on pos 1, hence the order is reversed.
// We want to make sure our traffic is not dropped by existing rules.

// The existing FORWARD rules/policies decide outbound traffic towards our interface.
// In case the FORWARD policy is set to "drop", we add an established/related rule to allow return traffic for the inbound rule.

// The OUTPUT chain gets an extra rule to allow traffic to any set up routes, the return traffic is handled by the INPUT related/established rule.
func (m *aclManager) seedInitialEntries() {

	established := getConntrackEstablished()

	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", chainNameInputRules})
	m.appendToEntries("INPUT", append([]string{"-i", m.wgIface.Name()}, established...))

	m.appendToEntries("OUTPUT", []string{"-o", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("OUTPUT", []string{"-o", m.wgIface.Name(), "-j", chainNameOutputRules})
	m.appendToEntries("OUTPUT", []string{"-o", m.wgIface.Name(), "!", "-d", m.wgIface.Address().String(), "-j", "ACCEPT"})
	m.appendToEntries("OUTPUT", append([]string{"-o", m.wgIface.Name()}, established...))

	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", m.routingFwChainName})
	m.appendToEntries("FORWARD", append([]string{"-o", m.wgIface.Name()}, established...))
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
