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
	tableFilter             = "filter"
	tableNat                = "nat"
	chainFORWARD            = "FORWARD"
	chainPOSTROUTING        = "POSTROUTING"
	chainRTNAT              = "NETBIRD-RT-NAT"
	chainRTFWD              = "NETBIRD-RT-FWD"
	routingFinalForwardJump = "ACCEPT"
	routingFinalNatJump     = "MASQUERADE"
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

	err := m.cleanUpDefaultForwardRules()
	if err != nil {
		log.Errorf("failed to cleanup routing rules: %s", err)
		return nil, err
	}
	err = m.createContainers()
	if err != nil {
		log.Errorf("failed to create containers for route: %s", err)
	}
	return m, err
}

// InsertRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *routerManager) InsertRoutingRules(pair firewall.RouterPair) error {
	err := i.insertRoutingRule(firewall.ForwardingFormat, tableFilter, chainRTFWD, routingFinalForwardJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(firewall.InForwardingFormat, tableFilter, chainRTFWD, routingFinalForwardJump, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	if !pair.Masquerade {
		return nil
	}

	err = i.insertRoutingRule(firewall.NatFormat, tableNat, chainRTNAT, routingFinalNatJump, pair)
	if err != nil {
		return err
	}

	err = i.insertRoutingRule(firewall.InNatFormat, tableNat, chainRTNAT, routingFinalNatJump, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	return nil
}

// insertRoutingRule inserts an iptables rule
func (i *routerManager) insertRoutingRule(keyFormat, table, chain, jump string, pair firewall.RouterPair) error {
	var err error

	ruleKey := firewall.GenKey(keyFormat, pair.ID)
	rule := genRuleSpec(jump, pair.Source, pair.Destination)
	existingRule, found := i.rules[ruleKey]
	if found {
		err = i.iptablesClient.DeleteIfExists(table, chain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
		}
		delete(i.rules, ruleKey)
	}
	err = i.iptablesClient.Insert(table, chain, 1, rule...)
	if err != nil {
		return fmt.Errorf("error while adding new %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
	}

	i.rules[ruleKey] = rule

	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *routerManager) RemoveRoutingRules(pair firewall.RouterPair) error {
	err := i.removeRoutingRule(firewall.ForwardingFormat, tableFilter, chainRTFWD, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(firewall.InForwardingFormat, tableFilter, chainRTFWD, firewall.GetInPair(pair))
	if err != nil {
		return err
	}

	if !pair.Masquerade {
		return nil
	}

	err = i.removeRoutingRule(firewall.NatFormat, tableNat, chainRTNAT, pair)
	if err != nil {
		return err
	}

	err = i.removeRoutingRule(firewall.InNatFormat, tableNat, chainRTNAT, firewall.GetInPair(pair))
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
			return fmt.Errorf("error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.Destination, err)
		}
	}
	delete(i.rules, ruleKey)

	return nil
}

func (i *routerManager) RouteingFwChainName() string {
	return chainRTFWD
}

func (i *routerManager) Reset() error {
	err := i.cleanUpDefaultForwardRules()
	if err != nil {
		return err
	}
	i.rules = make(map[string][]string)
	return nil
}

func (i *routerManager) cleanUpDefaultForwardRules() error {
	err := i.cleanJumpRules()
	if err != nil {
		return err
	}

	log.Debug("flushing routing related tables")
	ok, err := i.iptablesClient.ChainExists(tableFilter, chainRTFWD)
	if err != nil {
		log.Errorf("failed check chain %s,error: %v", chainRTFWD, err)
		return err
	} else if ok {
		err = i.iptablesClient.ClearAndDeleteChain(tableFilter, chainRTFWD)
		if err != nil {
			log.Errorf("failed cleaning chain %s,error: %v", chainRTFWD, err)
			return err
		}
	}

	ok, err = i.iptablesClient.ChainExists(tableNat, chainRTNAT)
	if err != nil {
		log.Errorf("failed check chain %s,error: %v", chainRTNAT, err)
		return err
	} else if ok {
		err = i.iptablesClient.ClearAndDeleteChain(tableNat, chainRTNAT)
		if err != nil {
			log.Errorf("failed cleaning chain %s,error: %v", chainRTNAT, err)
			return err
		}
	}
	return nil
}

func (i *routerManager) createContainers() error {
	if i.rules[Ipv4Forwarding] != nil {
		return nil
	}

	errMSGFormat := "failed creating chain %s,error: %v"
	err := i.createChain(tableFilter, chainRTFWD)
	if err != nil {
		return fmt.Errorf(errMSGFormat, chainRTFWD, err)
	}

	err = i.createChain(tableNat, chainRTNAT)
	if err != nil {
		return fmt.Errorf(errMSGFormat, chainRTNAT, err)
	}

	err = i.addJumpRules()
	if err != nil {
		return fmt.Errorf("error while creating jump rules: %v", err)
	}

	return nil
}

// addJumpRules create jump rules to send packets to NetBird chains
func (i *routerManager) addJumpRules() error {
	rule := []string{"-j", chainRTFWD}
	err := i.iptablesClient.Insert(tableFilter, chainFORWARD, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[Ipv4Forwarding] = rule

	rule = []string{"-j", chainRTNAT}
	err = i.iptablesClient.Insert(tableNat, chainPOSTROUTING, 1, rule...)
	if err != nil {
		return err
	}
	i.rules[ipv4Nat] = rule

	return nil
}

// cleanJumpRules cleans jump rules that was sending packets to NetBird chains
func (i *routerManager) cleanJumpRules() error {
	var err error
	errMSGFormat := "failed cleaning rule from chain %s,err: %v"
	rule, found := i.rules[Ipv4Forwarding]
	if found {
		err = i.iptablesClient.DeleteIfExists(tableFilter, chainFORWARD, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, chainFORWARD, err)
		}
	}
	rule, found = i.rules[ipv4Nat]
	if found {
		err = i.iptablesClient.DeleteIfExists(tableNat, chainPOSTROUTING, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, chainPOSTROUTING, err)
		}
	}

	rules, err := i.iptablesClient.List("nat", "POSTROUTING")
	if err != nil {
		return fmt.Errorf("failed to list rules: %s", err)
	}

	for _, ruleString := range rules {
		if !strings.Contains(ruleString, "NETBIRD") {
			continue
		}
		rule := strings.Fields(ruleString)
		err := i.iptablesClient.DeleteIfExists("nat", "POSTROUTING", rule[2:]...)
		if err != nil {
			return fmt.Errorf("failed to delete postrouting jump rule: %s", err)
		}
	}

	rules, err = i.iptablesClient.List(tableFilter, "FORWARD")
	if err != nil {
		return fmt.Errorf("failed to list rules in FORWARD chain: %s", err)
	}

	for _, ruleString := range rules {
		if !strings.Contains(ruleString, "NETBIRD") {
			continue
		}
		rule := strings.Fields(ruleString)
		err := i.iptablesClient.DeleteIfExists(tableFilter, "FORWARD", rule[2:]...)
		if err != nil {
			return fmt.Errorf("failed to delete FORWARD jump rule: %s", err)
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

		err = i.iptablesClient.Append(table, newChain, "-j", "RETURN")
		if err != nil {
			return fmt.Errorf("couldn't create chain %s default rule, error: %v", newChain, err)
		}

	}
	return nil
}

// genRuleSpec generates rule specification
func genRuleSpec(jump, source, destination string) []string {
	return []string{"-s", source, "-d", destination, "-j", jump}
}

func getIptablesRuleType(table string) string {
	ruleType := "forwarding"
	if table == tableNat {
		ruleType = "nat"
	}
	return ruleType
}
