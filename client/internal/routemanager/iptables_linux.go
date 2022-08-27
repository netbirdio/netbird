package routemanager

import (
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

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
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	rules      map[string]map[string][]string
	mux        sync.Mutex
}

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (i *iptablesManager) CleanRoutingRules() {
	i.mux.Lock()
	defer i.mux.Unlock()

	log.Debug("flushing tables")
	errMSGFormat := "iptables: failed cleaning %s chain %s,error: %v"
	err := i.ipv4Client.ClearAndDeleteChain(iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		log.Errorf(errMSGFormat, ipv4, iptablesRoutingForwardingChain, err)
	}

	err = i.ipv4Client.ClearAndDeleteChain(iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		log.Errorf(errMSGFormat, ipv4, iptablesRoutingNatChain, err)
	}

	err = i.ipv6Client.ClearAndDeleteChain(iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		log.Errorf(errMSGFormat, ipv6, iptablesRoutingForwardingChain, err)
	}

	err = i.ipv6Client.ClearAndDeleteChain(iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		log.Errorf(errMSGFormat, ipv6, iptablesRoutingNatChain, err)
	}

	err = i.cleanJumpRules()
	if err != nil {
		log.Error(err)
	}

	log.Info("done cleaning up iptables rules")
}

// RestoreOrCreateContainers restores existing iptables containers (chains and rules)
// if they don't exist, we create them
func (i *iptablesManager) RestoreOrCreateContainers() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	if i.rules[ipv4][ipv4Forwarding] != nil && i.rules[ipv6][ipv6Forwarding] != nil {
		return nil
	}

	errMSGFormat := "iptables: failed creating %s chain %s,error: %v"

	err := createChain(i.ipv4Client, iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, ipv4, iptablesRoutingForwardingChain, err)
	}

	err = createChain(i.ipv4Client, iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, ipv4, iptablesRoutingNatChain, err)
	}

	err = createChain(i.ipv6Client, iptablesFilterTable, iptablesRoutingForwardingChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, ipv6, iptablesRoutingForwardingChain, err)
	}

	err = createChain(i.ipv6Client, iptablesNatTable, iptablesRoutingNatChain)
	if err != nil {
		return fmt.Errorf(errMSGFormat, ipv6, iptablesRoutingNatChain, err)
	}

	err = i.restoreRules(i.ipv4Client)
	if err != nil {
		return fmt.Errorf("iptables: error while restoring ipv4 rules: %v", err)
	}

	err = i.restoreRules(i.ipv6Client)
	if err != nil {
		return fmt.Errorf("iptables: error while restoring ipv6 rules: %v", err)
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
	err = i.ipv4Client.Insert(iptablesFilterTable, iptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(iptablesDefaultNatRule, ipv4Nat)
	err = i.ipv4Client.Insert(iptablesNatTable, iptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(iptablesDefaultForwardingRule, ipv6Forwarding)
	err = i.ipv6Client.Insert(iptablesFilterTable, iptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(iptablesDefaultNatRule, ipv6Nat)
	err = i.ipv6Client.Insert(iptablesNatTable, iptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	return nil
}

// cleanJumpRules cleans jump rules that was sending packets to NetBird chains
func (i *iptablesManager) cleanJumpRules() error {
	var err error
	errMSGFormat := "iptables: failed cleaning rule from %s chain %s,err: %v"
	rule, found := i.rules[ipv4][ipv4Forwarding]
	if found {
		err = i.ipv4Client.DeleteIfExists(iptablesFilterTable, iptablesForwardChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, ipv4, iptablesForwardChain, err)
		}
	}
	rule, found = i.rules[ipv4][ipv4Nat]
	if found {
		err = i.ipv4Client.DeleteIfExists(iptablesNatTable, iptablesPostRoutingChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, ipv4, iptablesPostRoutingChain, err)
		}
	}
	rule, found = i.rules[ipv6][ipv6Forwarding]
	if found {
		err = i.ipv6Client.DeleteIfExists(iptablesFilterTable, iptablesForwardChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, ipv6, iptablesForwardChain, err)
		}
	}
	rule, found = i.rules[ipv6][ipv6Nat]
	if found {
		err = i.ipv6Client.DeleteIfExists(iptablesNatTable, iptablesPostRoutingChain, rule...)
		if err != nil {
			return fmt.Errorf(errMSGFormat, ipv6, iptablesPostRoutingChain, err)
		}
	}
	return nil
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}

// restoreRules restores existing NetBird rules
func (i *iptablesManager) restoreRules(iptablesClient *iptables.IPTables) error {
	ipVersion := iptablesProtoToString(iptablesClient.Proto())

	if i.rules[ipVersion] == nil {
		i.rules[ipVersion] = make(map[string][]string)
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
				i.rules[ipVersion][id] = rule[2:]
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
				i.rules[ipVersion][id] = rule[2:]
			}
		}
	}

	return nil
}

// createChain create NetBird chains
func createChain(iptables *iptables.IPTables, table, newChain string) error {
	chains, err := iptables.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s %s table chains, error: %v", iptablesProtoToString(iptables.Proto()), table, err)
	}

	shouldCreateChain := true
	for _, chain := range chains {
		if chain == newChain {
			shouldCreateChain = false
		}
	}

	if shouldCreateChain {
		err = iptables.NewChain(table, newChain)
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", iptablesProtoToString(iptables.Proto()), newChain, table, err)
		}

		if table == iptablesNatTable {
			err = iptables.Append(table, newChain, iptablesDefaultNetbirdNatRule...)
		} else {
			err = iptables.Append(table, newChain, iptablesDefaultNetbirdForwardingRule...)
		}
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s default rule, error: %v", iptablesProtoToString(iptables.Proto()), newChain, err)
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

	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = ipv6
	}

	forwardRuleKey := genKey(forwardingFormat, pair.ID)
	forwardRule := genRuleSpec(routingFinalForwardJump, forwardRuleKey, pair.source, pair.destination)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(iptablesFilterTable, iptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing forwarding rule for %s: %v", pair.destination, err)
		}
		delete(i.rules[ipVersion], forwardRuleKey)
	}
	err = iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forwardRule...)
	if err != nil {
		return fmt.Errorf("iptables: error while adding new forwarding rule for %s: %v", pair.destination, err)
	}

	i.rules[ipVersion][forwardRuleKey] = forwardRule

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(natFormat, pair.ID)
	natRule := genRuleSpec(routingFinalNatJump, natRuleKey, pair.source, pair.destination)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(iptablesNatTable, iptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing nat rulefor %s: %v", pair.destination, err)
		}
		delete(i.rules[ipVersion], natRuleKey)
	}
	err = iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, natRule...)
	if err != nil {
		return fmt.Errorf("iptables: error while adding new nat rulefor %s: %v", pair.destination, err)
	}

	i.rules[ipVersion][natRuleKey] = natRule

	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) RemoveRoutingRules(pair routerPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = ipv6
	}

	forwardRuleKey := genKey(forwardingFormat, pair.ID)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(iptablesFilterTable, iptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing forwarding rule for %s: %v", pair.destination, err)
		}
	}
	delete(i.rules[ipVersion], forwardRuleKey)

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(natFormat, pair.ID)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(iptablesNatTable, iptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing nat rule for %s: %v", pair.destination, err)
		}
	}
	delete(i.rules[ipVersion], natRuleKey)

	return nil
}
