//go:build !android

package routemanager

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
)

// constants needed to manage and create iptable rules
const (
	iptablesFilterTable            = "filter"
	iptablesNatTable               = "nat"
	iptablesForwardChain           = "FORWARD"
	iptablesPostRoutingChain       = "POSTROUTING"
	iptablesRoutingNatChain        = "NETBIRD-RT-NAT"
	iptablesRoutingForwardingChain = "NETBIRD-RT-FWD"
	routingFinalForwardJump        = "ACCEPT"
	routingFinalNatJump            = "MASQUERADE"
)

// some presets for building nftable rules
var (
	iptablesDefaultForwardingRule        = []string{"-j", iptablesRoutingForwardingChain, "-m", "comment", "--comment"}
	iptablesDefaultNetbirdForwardingRule = []string{"-j", "RETURN"}
	iptablesDefaultNatRule               = []string{"-j", iptablesRoutingNatChain, "-m", "comment", "--comment"}
	iptablesDefaultNetbirdNatRule        = []string{"-j", "RETURN"}
)

type iptablesManager struct {
	ctx            context.Context
	stop           context.CancelFunc
	iptablesClient *iptables.IPTables
	rules          map[string][]string
	mux            sync.Mutex
}

func newIptablesManager(parentCtx context.Context) (*iptablesManager, error) {
	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables for ipv4: %s", err)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	manager := &iptablesManager{
		ctx:            ctx,
		stop:           cancel,
		iptablesClient: client,
		rules:          make(map[string][]string),
	}
	return manager, nil
}

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (i *iptablesManager) CleanRoutingRules() {
	i.mux.Lock()
	defer i.mux.Unlock()

	err := i.cleanJumpRules()
	if err != nil {
		log.Error(err)
	}

	log.Debug("flushing tables")
	errMSGFormat := "iptables: failed cleaning chain %s,error: %v"
	err = i.iptablesClient.ClearAndDeleteChain(iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		log.Errorf(errMSGFormat, iptablesRoutingForwardingChain, err)
	}

	err = i.iptablesClient.ClearAndDeleteChain(iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		log.Errorf(errMSGFormat, iptablesRoutingNatChain, err)
	}

	log.Info("done cleaning up iptables rules")
}

// RestoreOrCreateContainers restores existing iptables containers (chains and rules)
// if they don't exist, we create them
func (i *iptablesManager) RestoreOrCreateContainers() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	if i.rules[ipv4Forwarding] != nil {
		return nil
	}

	errMSGFormat := "iptables: failed creating chain %s,error: %v"

	err := i.createChain(iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, iptablesRoutingForwardingChain, err)
	}

	err = i.createChain(iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, iptablesRoutingNatChain, err)
	}

	err = i.restoreRules(i.iptablesClient)
	if err != nil {
		return fmt.Errorf("iptables: error while restoring ipv4 rules: %v", err)
	}

	err = i.addJumpRules()
	if err != nil {
		return fmt.Errorf("iptables: error while creating jump rules: %v", err)
	}

	return nil
}

// addJumpRules create jump rules to send packets to NetBird chains
func (i *iptablesManager) addJumpRules() error {
	err := i.cleanJumpRules()
	if err != nil {
		return err
	}

	rule := append(iptablesDefaultForwardingRule, ipv4Forwarding)

	err = i.iptablesClient.Insert(iptablesFilterTable, iptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[ipv4Forwarding] = rule

	rule = append(iptablesDefaultNatRule, ipv4Nat)
	err = i.iptablesClient.Insert(iptablesNatTable, iptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[ipv4Nat] = rule

	return nil
}

// cleanJumpRules cleans jump rules that was sending packets to NetBird chains
func (i *iptablesManager) cleanJumpRules() error {
	var err error
	errMSGFormat := "iptables: failed cleaning rule from chain %s,err: %v"
	rule, found := i.rules[ipv4Forwarding]
	if found {
		log.Debugf("iptables: removing rule: %s ", ipv4Forwarding)
		err = i.iptablesClient.DeleteIfExists(iptablesFilterTable, iptablesForwardChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, iptablesForwardChain, err)
		}
	}
	rule, found = i.rules[ipv4Nat]
	if found {
		log.Debugf("iptables: removing rule: %s ", ipv4Nat)
		err = i.iptablesClient.DeleteIfExists(iptablesNatTable, iptablesPostRoutingChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, iptablesPostRoutingChain, err)
		}
	}
	return nil
}

// restoreRules restores existing NetBird rules
func (i *iptablesManager) restoreRules(iptablesClient *iptables.IPTables) error {
	if i.rules == nil {
		i.rules = make(map[string][]string)
	}
	table := iptablesFilterTable
	for _, chain := range []string{iptablesForwardChain, iptablesRoutingForwardingChain} {
		rules, err := iptablesClient.List(table, chain)
		if err != nil {
			return err
		}
		for _, ruleString := range rules {
			rule := strings.Fields(ruleString)
			id := getRuleRouteID(rule)
			if id != "" {
				i.rules[id] = rule[2:]
			}
		}
	}

	table = iptablesNatTable
	for _, chain := range []string{iptablesPostRoutingChain, iptablesRoutingNatChain} {
		rules, err := iptablesClient.List(table, chain)
		if err != nil {
			return err
		}
		for _, ruleString := range rules {
			rule := strings.Fields(ruleString)
			id := getRuleRouteID(rule)
			if id != "" {
				i.rules[id] = rule[2:]
			}
		}
	}

	return nil
}

// createChain create NetBird chains
func (i *iptablesManager) createChain(table, newChain string) error {
	chains, err := i.iptablesClient.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s table chains, error: %v", table, err)
	}

	shouldCreateChain := true
	for _, chain := range chains {
		if chain == newChain {
			shouldCreateChain = false
		}
	}

	if shouldCreateChain {
		err = i.iptablesClient.NewChain(table, newChain)
		if err != nil {
			return fmt.Errorf("couldn't create chain %s in %s table, error: %v", newChain, table, err)
		}

		if table == iptablesNatTable {
			err = i.iptablesClient.Append(table, newChain, iptablesDefaultNetbirdNatRule...)
		} else {
			err = i.iptablesClient.Append(table, newChain, iptablesDefaultNetbirdForwardingRule...)
		}
		if err != nil {
			return fmt.Errorf("couldn't create chain %s default rule, error: %v", newChain, err)
		}

	}
	return nil
}

// genRuleSpec generates rule specification with comment identifier
func genRuleSpec(jump, id, source, destination string) []string {
	return []string{"-s", source, "-d", destination, "-j", jump, "-m", "comment", "--comment", id}
}

// getRuleRouteID returns the rule ID if matches our prefix
func getRuleRouteID(rule []string) string {
	for i, flag := range rule {
		if flag == "--comment" {
			id := rule[i+1]
			if strings.HasPrefix(id, "netbird-") {
				return id
			}
		}
	}
	return ""
}

// InsertRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *iptablesManager) InsertRoutingRules(pair routerPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	err := i.insertRoutingRule(forwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, routingFinalForwardJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(inForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, routingFinalForwardJump, getInPair(pair))
	if err != nil {
		return err
	}

	if !pair.masquerade {
		return nil
	}

	err = i.insertRoutingRule(natFormat, iptablesNatTable, iptablesRoutingNatChain, routingFinalNatJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(inNatFormat, iptablesNatTable, iptablesRoutingNatChain, routingFinalNatJump, getInPair(pair))
	if err != nil {
		return err
	}

	return nil
}

// insertRoutingRule inserts an iptable rule
func (i *iptablesManager) insertRoutingRule(keyFormat, table, chain, jump string, pair routerPair) error {
	var err error

	ruleKey := genKey(keyFormat, pair.ID)
	rule := genRuleSpec(jump, ruleKey, pair.source, pair.destination)
	existingRule, found := i.rules[ruleKey]
	if found {
		err = i.iptablesClient.DeleteIfExists(table, chain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.destination, err)
		}
		delete(i.rules, ruleKey)
	}
	err = i.iptablesClient.Insert(table, chain, 1, rule...)
	if err != nil {
		return fmt.Errorf("iptables: error while adding new %s rule for %s: %v", getIptablesRuleType(table), pair.destination, err)
	}

	i.rules[ruleKey] = rule

	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) RemoveRoutingRules(pair routerPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	err := i.removeRoutingRule(forwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(inForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, getInPair(pair))
	if err != nil {
		return err
	}

	if !pair.masquerade {
		return nil
	}

	err = i.removeRoutingRule(natFormat, iptablesNatTable, iptablesRoutingNatChain, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(inNatFormat, iptablesNatTable, iptablesRoutingNatChain, getInPair(pair))
	if err != nil {
		return err
	}

	return nil
}

// removeRoutingRule removes an iptables rule
func (i *iptablesManager) removeRoutingRule(keyFormat, table, chain string, pair routerPair) error {
	var err error

	ruleKey := genKey(keyFormat, pair.ID)
	existingRule, found := i.rules[ruleKey]
	if found {
		err = i.iptablesClient.DeleteIfExists(table, chain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.destination, err)
		}
	}
	delete(i.rules, ruleKey)

	return nil
}

func getIptablesRuleType(table string) string {
	ruleType := "forwarding"
	if table == iptablesNatTable {
		ruleType = "nat"
	}
	return ruleType
}
