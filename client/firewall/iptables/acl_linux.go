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
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

const (
	tableName = "filter"

	// rules chains contains the effective ACL rules
	chainNameInputRules = "NETBIRD-ACL-INPUT"
)

type aclEntries map[string][][]string

type entry struct {
	spec     []string
	position int
}

type aclManager struct {
	iptablesClient     *iptables.IPTables
	wgIface            iFaceMapper
	routingFwChainName string

	entries         aclEntries
	optionalEntries map[string][]entry
	ipsetStore      *ipsetStore

	stateManager *statemanager.Manager
}

func newAclManager(iptablesClient *iptables.IPTables, wgIface iFaceMapper, routingFwChainName string) (*aclManager, error) {
	m := &aclManager{
		iptablesClient:     iptablesClient,
		wgIface:            wgIface,
		routingFwChainName: routingFwChainName,

		entries:         make(map[string][][]string),
		optionalEntries: make(map[string][]entry),
		ipsetStore:      newIpsetStore(),
	}

	if err := ipset.Init(); err != nil {
		return nil, fmt.Errorf("init ipset: %w", err)
	}

	return m, nil
}

func (m *aclManager) init(stateManager *statemanager.Manager) error {
	m.stateManager = stateManager

	m.seedInitialEntries()
	m.seedInitialOptionalEntries()

	if err := m.cleanChains(); err != nil {
		return fmt.Errorf("clean chains: %w", err)
	}

	if err := m.createDefaultChains(); err != nil {
		return fmt.Errorf("create default chains: %w", err)
	}

	m.updateState()

	return nil
}

func (m *aclManager) AddPeerFiltering(
	ip net.IP,
	protocol firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
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

	chain := chainNameInputRules

	ipsetName = transformIPsetName(ipsetName, sPortVal, dPortVal)
	specs := filterRuleSpecs(ip, string(protocol), sPortVal, dPortVal, action, ipsetName)
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

	m.updateState()

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

	if err := m.iptablesClient.Delete(tableName, r.chain, r.specs...); err != nil {
		return fmt.Errorf("failed to delete rule: %s, %v: %w", r.chain, r.specs, err)
	}

	m.updateState()

	return nil
}

func (m *aclManager) Reset() error {
	if err := m.cleanChains(); err != nil {
		return fmt.Errorf("clean chains: %w", err)
	}

	m.updateState()

	return nil
}

// todo write less destructive cleanup mechanism
func (m *aclManager) cleanChains() error {
	ok, err := m.iptablesClient.ChainExists(tableName, chainNameInputRules)
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
		return fmt.Errorf("list chains: %w", err)
	}
	if ok {
		for _, rule := range m.entries["PREROUTING"] {
			err := m.iptablesClient.DeleteIfExists("mangle", "PREROUTING", rule...)
			if err != nil {
				log.Errorf("failed to delete rule: %v, %s", rule, err)
			}
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

	for chainName, rules := range m.entries {
		for _, rule := range rules {
			if err := m.iptablesClient.InsertUnique(tableName, chainName, 1, rule...); err != nil {
				log.Debugf("failed to create input chain jump rule: %s", err)
				return err
			}
		}
	}

	for chainName, entries := range m.optionalEntries {
		for _, entry := range entries {
			if err := m.iptablesClient.InsertUnique(tableName, chainName, entry.position, entry.spec...); err != nil {
				log.Errorf("failed to insert optional entry %v: %v", entry.spec, err)
				continue
			}
			m.entries[chainName] = append(m.entries[chainName], entry.spec)
		}
	}
	clear(m.optionalEntries)

	return nil
}

// seedInitialEntries adds default rules to the entries map, rules are inserted on pos 1, hence the order is reversed.
// We want to make sure our traffic is not dropped by existing rules.

// The existing FORWARD rules/policies decide outbound traffic towards our interface.
// In case the FORWARD policy is set to "drop", we add an established/related rule to allow return traffic for the inbound rule.
func (m *aclManager) seedInitialEntries() {
	established := getConntrackEstablished()

	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("INPUT", []string{"-i", m.wgIface.Name(), "-j", chainNameInputRules})
	m.appendToEntries("INPUT", append([]string{"-i", m.wgIface.Name()}, established...))

	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", "DROP"})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", m.routingFwChainName})
	m.appendToEntries("FORWARD", append([]string{"-o", m.wgIface.Name()}, established...))
}

func (m *aclManager) seedInitialOptionalEntries() {
	m.optionalEntries["FORWARD"] = []entry{
		{
			spec:     []string{"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected), "-j", chainNameInputRules},
			position: 2,
		},
	}

	m.optionalEntries["PREROUTING"] = []entry{
		{
			spec:     []string{"-t", "mangle", "-i", m.wgIface.Name(), "-m", "addrtype", "--dst-type", "LOCAL", "-j", "MARK", "--set-mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected)},
			position: 1,
		},
	}
}

func (m *aclManager) appendToEntries(chainName string, spec []string) {
	m.entries[chainName] = append(m.entries[chainName], spec)
}

func (m *aclManager) updateState() {
	if m.stateManager == nil {
		return
	}

	var currentState *ShutdownState
	if existing := m.stateManager.GetState(currentState); existing != nil {
		if existingState, ok := existing.(*ShutdownState); ok {
			currentState = existingState
		}
	}
	if currentState == nil {
		currentState = &ShutdownState{}
	}

	currentState.Lock()
	defer currentState.Unlock()

	currentState.ACLEntries = m.entries
	currentState.ACLIPsetStore = m.ipsetStore

	if err := m.stateManager.UpdateState(currentState); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}

// filterRuleSpecs returns the specs of a filtering rule
func filterRuleSpecs(ip net.IP, protocol, sPort, dPort string, action firewall.Action, ipsetName string) (specs []string) {
	matchByIP := true
	// don't use IP matching if IP is ip 0.0.0.0
	if ip.String() == "0.0.0.0" {
		matchByIP = false
	}

	if matchByIP {
		if ipsetName != "" {
			specs = append(specs, "-m", "set", "--set", ipsetName, "src")
		} else {
			specs = append(specs, "-s", ip.String())
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
