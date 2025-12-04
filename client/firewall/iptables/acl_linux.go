package iptables

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	ipset "github.com/lrh3321/ipset-go"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
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
	iptablesClient  *iptables.IPTables
	wgIface         iFaceMapper
	entries         aclEntries
	optionalEntries map[string][]entry
	ipsetStore      *ipsetStore

	stateManager *statemanager.Manager
}

func newAclManager(iptablesClient *iptables.IPTables, wgIface iFaceMapper) (*aclManager, error) {
	return &aclManager{
		iptablesClient:  iptablesClient,
		wgIface:         wgIface,
		entries:         make(map[string][][]string),
		optionalEntries: make(map[string][]entry),
		ipsetStore:      newIpsetStore(),
	}, nil
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
	id []byte,
	ip net.IP,
	protocol firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
	ipsetName string,
) ([]firewall.Rule, error) {
	chain := chainNameInputRules

	ipsetName = transformIPsetName(ipsetName, sPort, dPort, action)
	specs := filterRuleSpecs(ip, string(protocol), sPort, dPort, action, ipsetName)

	mangleSpecs := slices.Clone(specs)
	mangleSpecs = append(mangleSpecs,
		"-i", m.wgIface.Name(),
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected),
	)

	specs = append(specs, "-j", actionToStr(action))
	if ipsetName != "" {
		if ipList, ipsetExists := m.ipsetStore.ipset(ipsetName); ipsetExists {
			if err := m.addToIPSet(ipsetName, ip); err != nil {
				return nil, fmt.Errorf("add IP to ipset: %w", err)
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

		if err := m.flushIPSet(ipsetName); err != nil {
			if errors.Is(err, ipset.ErrSetNotExist) {
				log.Debugf("flush ipset %s before use: %v", ipsetName, err)
			} else {
				log.Errorf("flush ipset %s before use: %v", ipsetName, err)
			}
		}
		if err := m.createIPSet(ipsetName); err != nil {
			return nil, fmt.Errorf("create ipset: %w", err)
		}
		if err := m.addToIPSet(ipsetName, ip); err != nil {
			return nil, fmt.Errorf("add IP to ipset: %w", err)
		}

		ipList := newIpList(ip.String())
		m.ipsetStore.addIpList(ipsetName, ipList)
	}

	ok, err := m.iptablesClient.Exists(tableFilter, chain, specs...)
	if err != nil {
		return nil, fmt.Errorf("failed to check rule: %w", err)
	}
	if ok {
		return nil, fmt.Errorf("rule already exists")
	}

	// Insert DROP rules at the beginning, append ACCEPT rules at the end
	if action == firewall.ActionDrop {
		// Insert at the beginning of the chain (position 1)
		err = m.iptablesClient.Insert(tableFilter, chain, 1, specs...)
	} else {
		err = m.iptablesClient.Append(tableFilter, chain, specs...)
	}
	if err != nil {
		return nil, err
	}

	if err := m.iptablesClient.Append(tableMangle, chainRTPRE, mangleSpecs...); err != nil {
		log.Errorf("failed to add mangle rule: %v", err)
		mangleSpecs = nil
	}

	rule := &Rule{
		ruleID:      uuid.New().String(),
		specs:       specs,
		mangleSpecs: mangleSpecs,
		ipsetName:   ipsetName,
		ip:          ip.String(),
		chain:       chain,
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

	shouldDestroyIpset := false
	if ipsetList, ok := m.ipsetStore.ipset(r.ipsetName); ok {
		// delete IP from ruleset IPs list and ipset
		if _, ok := ipsetList.ips[r.ip]; ok {
			ip := net.ParseIP(r.ip)
			if ip == nil {
				return fmt.Errorf("parse IP %s", r.ip)
			}
			if err := m.delFromIPSet(r.ipsetName, ip); err != nil {
				return fmt.Errorf("delete ip from ipset: %w", err)
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
		shouldDestroyIpset = true
	}

	if err := m.iptablesClient.Delete(tableName, r.chain, r.specs...); err != nil {
		return fmt.Errorf("failed to delete rule: %s, %v: %w", r.chain, r.specs, err)
	}

	if r.mangleSpecs != nil {
		if err := m.iptablesClient.Delete(tableMangle, chainRTPRE, r.mangleSpecs...); err != nil {
			log.Errorf("failed to delete mangle rule: %v", err)
		}
	}

	if shouldDestroyIpset {
		if err := m.destroyIPSet(r.ipsetName); err != nil {
			if errors.Is(err, ipset.ErrBusy) || errors.Is(err, ipset.ErrSetNotExist) {
				log.Debugf("destroy empty ipset: %v", err)
			} else {
				log.Errorf("destroy empty ipset: %v", err)
			}
		}
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
		if err := m.flushIPSet(ipsetName); err != nil {
			if errors.Is(err, ipset.ErrSetNotExist) {
				log.Debugf("flush ipset %q during reset: %v", ipsetName, err)
			} else {
				log.Errorf("flush ipset %q during reset: %v", ipsetName, err)
			}
		}
		if err := m.destroyIPSet(ipsetName); err != nil {
			if errors.Is(err, ipset.ErrBusy) || errors.Is(err, ipset.ErrSetNotExist) {
				log.Debugf("destroy ipset %q during reset: %v", ipsetName, err)
			} else {
				log.Errorf("destroy ipset %q during reset: %v", ipsetName, err)
			}
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

	// Inbound is handled by our ACLs, the rest is dropped.
	// For outbound we respect the FORWARD policy. However, we need to allow established/related traffic for inbound rules.
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", "DROP"})

	m.appendToEntries("FORWARD", []string{"-o", m.wgIface.Name(), "-j", chainRTFWDOUT})
	m.appendToEntries("FORWARD", []string{"-i", m.wgIface.Name(), "-j", chainRTFWDIN})
}

func (m *aclManager) seedInitialOptionalEntries() {
	m.optionalEntries["FORWARD"] = []entry{
		{
			spec:     []string{"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected), "-j", "ACCEPT"},
			position: 2,
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
func filterRuleSpecs(ip net.IP, protocol string, sPort, dPort *firewall.Port, action firewall.Action, ipsetName string) (specs []string) {
	// don't use IP matching if IP is 0.0.0.0
	matchByIP := !ip.IsUnspecified()

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
	specs = append(specs, applyPort("--sport", sPort)...)
	specs = append(specs, applyPort("--dport", dPort)...)
	return specs
}

func actionToStr(action firewall.Action) string {
	if action == firewall.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}

func transformIPsetName(ipsetName string, sPort, dPort *firewall.Port, action firewall.Action) string {
	if ipsetName == "" {
		return ""
	}

	actionSuffix := ""
	if action == firewall.ActionDrop {
		actionSuffix = "-drop"
	}

	switch {
	case sPort != nil && dPort != nil:
		return ipsetName + "-sport-dport" + actionSuffix
	case sPort != nil:
		return ipsetName + "-sport" + actionSuffix
	case dPort != nil:
		return ipsetName + "-dport" + actionSuffix
	default:
		return ipsetName + actionSuffix
	}
}

func (m *aclManager) createIPSet(name string) error {
	opts := ipset.CreateOptions{
		Replace: true,
	}

	if err := ipset.Create(name, ipset.TypeHashNet, opts); err != nil {
		return fmt.Errorf("create ipset %s: %w", name, err)
	}

	log.Debugf("created ipset %s with type hash:net", name)
	return nil
}

func (m *aclManager) addToIPSet(name string, ip net.IP) error {
	cidr := uint8(32)
	if ip.To4() == nil {
		cidr = 128
	}

	entry := &ipset.Entry{
		IP:      ip,
		CIDR:    cidr,
		Replace: true,
	}

	if err := ipset.Add(name, entry); err != nil {
		return fmt.Errorf("add IP to ipset %s: %w", name, err)
	}

	return nil
}

func (m *aclManager) delFromIPSet(name string, ip net.IP) error {
	cidr := uint8(32)
	if ip.To4() == nil {
		cidr = 128
	}

	entry := &ipset.Entry{
		IP:   ip,
		CIDR: cidr,
	}

	if err := ipset.Del(name, entry); err != nil {
		return fmt.Errorf("delete IP from ipset %s: %w", name, err)
	}

	return nil
}

func (m *aclManager) flushIPSet(name string) error {
	return ipset.Flush(name)
}

func (m *aclManager) destroyIPSet(name string) error {
	return ipset.Destroy(name)
}
