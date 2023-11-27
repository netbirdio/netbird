//go:build !android

package iptables

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	Ipv4Forwarding = "netbird-rt-forwarding"
	ipv4Nat        = "netbird-rt-nat"
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

type routerManager struct {
	ctx            context.Context
	stop           context.CancelFunc
	iptablesClient *iptables.IPTables
	rules          map[string][]string
}

func newRouterManager(parentCtx context.Context, iptablesClient *iptables.IPTables) (*routerManager, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	m := &routerManager{
		ctx:            ctx,
		stop:           cancel,
		iptablesClient: iptablesClient,
		rules:          make(map[string][]string),
	}

	m.cleanUpDefaultForwardRules()
	err := m.restoreOrCreateContainers()
	if err != nil {
		log.Errorf("failed to create containers for route: %s", err)
	}
	return m, err
}

// InsertRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *routerManager) InsertRoutingRules(pair firewall.RouterPair) error {
	err := i.insertRoutingRule(firewall.ForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, routingFinalForwardJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(firewall.InForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, routingFinalForwardJump, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	if !pair.Masquerade {
		return nil
	}

	err = i.insertRoutingRule(firewall.NatFormat, iptablesNatTable, iptablesRoutingNatChain, routingFinalNatJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(firewall.InNatFormat, iptablesNatTable, iptablesRoutingNatChain, routingFinalNatJump, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	return nil
}

// insertRoutingRule inserts an iptable rule
func (i *routerManager) insertRoutingRule(keyFormat, table, chain, jump string, pair firewall.RouterPair) error {
	var err error

	ruleKey := firewall.GenKey(keyFormat, pair.ID)
	rule := genRuleSpec(jump, ruleKey, pair.Source, pair.Destination)
	existingRule, found := i.rules[ruleKey]
	if found {
		err = i.iptablesClient.DeleteIfExists(table, chain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
		}
		delete(i.rules, ruleKey)
	}
	err = i.iptablesClient.Insert(table, chain, 1, rule...)
	if err != nil {
		return fmt.Errorf("iptables: error while adding new %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
	}

	i.rules[ruleKey] = rule

	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *routerManager) RemoveRoutingRules(pair firewall.RouterPair) error {
	err := i.removeRoutingRule(firewall.ForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(firewall.InForwardingFormat, iptablesFilterTable, iptablesRoutingForwardingChain, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	if !pair.Masquerade {
		return nil
	}

	err = i.removeRoutingRule(firewall.NatFormat, iptablesNatTable, iptablesRoutingNatChain, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(firewall.InNatFormat, iptablesNatTable, iptablesRoutingNatChain, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	return nil
}

func (i *routerManager) removeRoutingRule(keyFormat, table, chain string, pair firewall.RouterPair) error {
	var err error

	ruleKey := firewall.GenKey(keyFormat, pair.ID)
	existingRule, found := i.rules[ruleKey]
	if found {
		err = i.iptablesClient.DeleteIfExists(table, chain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
		}
	}
	delete(i.rules, ruleKey)

	return nil
}

func (i *routerManager) RouteingFwChainName() string {
	return iptablesRoutingForwardingChain
}

func (i *routerManager) Reset() error {
	i.cleanUpDefaultForwardRules()
	return nil
}

func (i *routerManager) cleanUpDefaultForwardRules() {
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

func (i *routerManager) restoreOrCreateContainers() error {
	if i.rules[Ipv4Forwarding] != nil {
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
func (i *routerManager) addJumpRules() error {
	err := i.cleanJumpRules()
	if err != nil {
		return err
	}

	rule := []string{"-j", iptablesRoutingForwardingChain}
	err = i.iptablesClient.Insert(iptablesFilterTable, iptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[Ipv4Forwarding] = rule

	rule = []string{"-j", iptablesRoutingNatChain}
	err = i.iptablesClient.Insert(iptablesNatTable, iptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[ipv4Nat] = rule

	return nil
}

// cleanJumpRules cleans jump rules that was sending packets to NetBird chains
func (i *routerManager) cleanJumpRules() error {
	var err error
	errMSGFormat := "iptables: failed cleaning rule from chain %s,err: %v"
	rule, found := i.rules[Ipv4Forwarding]
	if found {
		log.Debugf("iptables: removing rule: %s, %v ", Ipv4Forwarding, rule)
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

func (i *routerManager) restoreRules(iptablesClient *iptables.IPTables) error {
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

func (i *routerManager) createChain(table, newChain string) error {
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
			err = i.iptablesClient.Append(table, newChain, "-j", "RETURN")
		} else {
			err = i.iptablesClient.Append(table, newChain, "-j", "RETURN")
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

func getIptablesRuleType(table string) string {
	ruleType := "forwarding"
	if table == iptablesNatTable {
		ruleType = "nat"
	}
	return ruleType
}
