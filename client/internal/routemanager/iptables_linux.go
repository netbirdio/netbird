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

const (
	IptablesFilterTable            = "filter"
	IptablesNatTable               = "nat"
	IptablesForwardChain           = "FORWARD"
	IptablesPostRoutingChain       = "POSTROUTING"
	IptablesRoutingNatChain        = "NETBIRD-RT-NAT"
	IptablesRoutingForwardingChain = "NETBIRD-RT-FWD"
	RoutingFinalForwardJump        = "ACCEPT"
	RoutingFinalNatJump            = "MASQUERADE"
)

var IptablesDefaultForwardingRule = []string{"-j", IptablesRoutingForwardingChain, "-m", "comment", "--comment"}
var IptablesDefaultNetbirdForwardingRule = []string{"-j", "RETURN"}
var IptablesDefaultNatRule = []string{"-j", IptablesRoutingNatChain, "-m", "comment", "--comment"}
var IptablesDefaultNetbirdNatRule = []string{"-j", "RETURN"}

type iptablesManager struct {
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	rules      map[string]map[string][]string
	mux        sync.Mutex
}

func (i *iptablesManager) CleanRoutingRules() {
	i.mux.Lock()
	defer i.mux.Unlock()
	log.Debug("flushing tables")
	err := i.ipv4Client.ClearAndDeleteChain(IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Error(err)
	}
	err = i.ipv4Client.ClearAndDeleteChain(IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Error(err)
	}
	err = i.ipv6Client.ClearAndDeleteChain(IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Error(err)
	}
	err = i.ipv6Client.ClearAndDeleteChain(IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Error(err)
	}

	err = i.cleanJumpRules()
	//todo
	if err != nil {
		log.Error(err)
	}

	log.Info("done cleaning up iptables rules")
}
func (i *iptablesManager) RestoreOrCreateContainers() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	if i.rules[Ipv4][Ipv4Forwarding] != nil && i.rules[Ipv6][Ipv6Forwarding] != nil {
		return nil
	}

	err := createChain(i.ipv4Client, IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv4Client, IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv6Client, IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv6Client, IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}

	// ensure we jump to our chains in the default chains
	err = i.restoreRules(i.ipv4Client)
	//todo
	if err != nil {
		log.Fatal("error while restoring ipv4 rules: ", err)
	}
	err = i.restoreRules(i.ipv6Client)
	//todo
	if err != nil {
		log.Fatal("error while restoring ipv6 rules: ", err)
	}

	for version := range i.rules {
		for key, value := range i.rules[version] {
			log.Debugf("%s rule %s after restore: %#v\n", version, key, value)
		}
	}

	err = i.addJumpRules()
	//todo
	if err != nil {
		log.Fatal("error while creating jump rules: ", err)
	}

	return nil
}

func (i *iptablesManager) addJumpRules() error {
	err := i.cleanJumpRules()
	if err != nil {
		return err
	}
	rule := append(IptablesDefaultForwardingRule, Ipv4Forwarding)
	err = i.ipv4Client.Insert(IptablesFilterTable, IptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultNatRule, Ipv4Nat)
	err = i.ipv4Client.Insert(IptablesNatTable, IptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultForwardingRule, Ipv6Forwarding)
	err = i.ipv6Client.Insert(IptablesFilterTable, IptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultNatRule, Ipv6Nat)
	err = i.ipv6Client.Insert(IptablesNatTable, IptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	return nil
}

func (i *iptablesManager) cleanJumpRules() error {
	var err error
	rule, found := i.rules[Ipv4][Ipv4Forwarding]
	if found {
		err = i.ipv4Client.DeleteIfExists(IptablesFilterTable, IptablesForwardChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv4][Ipv4Nat]
	if found {
		err = i.ipv4Client.DeleteIfExists(IptablesNatTable, IptablesPostRoutingChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv6][Ipv4Forwarding]
	if found {
		err = i.ipv6Client.DeleteIfExists(IptablesFilterTable, IptablesForwardChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv6][Ipv4Nat]
	if found {
		err = i.ipv6Client.DeleteIfExists(IptablesNatTable, IptablesPostRoutingChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *iptablesManager) restoreRules(iptablesClient *iptables.IPTables) error {
	var ipVersion string
	switch iptablesClient.Proto() {
	case iptables.ProtocolIPv4:
		ipVersion = Ipv4
	case iptables.ProtocolIPv6:
		ipVersion = Ipv6
	}

	if i.rules[ipVersion] == nil {
		i.rules[ipVersion] = make(map[string][]string)
	}
	table := IptablesFilterTable
	for _, chain := range []string{IptablesForwardChain, IptablesRoutingForwardingChain} {
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

	table = IptablesNatTable
	for _, chain := range []string{IptablesPostRoutingChain, IptablesRoutingNatChain} {
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

func createChain(iptables *iptables.IPTables, table, newChain string) error {
	chains, err := iptables.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s %s table chains, error: %v", iptables.Proto(), table, err)
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
			return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", newChain, iptables.Proto(), table, err)
		}

		if table == IptablesNatTable {
			err = iptables.Append(table, newChain, IptablesDefaultNetbirdNatRule...)
		} else {
			err = iptables.Append(table, newChain, IptablesDefaultNetbirdForwardingRule...)
		}
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s default rule, error: %v", newChain, iptables.Proto(), err)
		}

	}
	return nil
}

func genRuleSpec(jump, id, source, destination string) []string {
	return []string{"-s", source, "-d", destination, "-j", jump, "-m", "comment", "--comment", id}
}

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

func (i *iptablesManager) InsertRoutingRules(pair RouterPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := Ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = Ipv6
	}

	forwardRuleKey := genKey(ForwardingFormat, pair.ID)
	forwardRule := genRuleSpec(RoutingFinalForwardJump, forwardRuleKey, pair.source, pair.destination)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesFilterTable, IptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing forwarding rule, error: %v", err)
		}
		delete(i.rules[ipVersion], forwardRuleKey)
	}
	err = iptablesClient.Insert(IptablesFilterTable, IptablesRoutingForwardingChain, 1, forwardRule...)
	if err != nil {
		return fmt.Errorf("error while adding new forwarding rule, error: %v", err)
	}

	i.rules[ipVersion][forwardRuleKey] = forwardRule

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(NatFormat, pair.ID)
	natRule := genRuleSpec(RoutingFinalNatJump, natRuleKey, pair.source, pair.destination)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesNatTable, IptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing nat rule, error: %v", err)
		}
		delete(i.rules[ipVersion], natRuleKey)
	}
	err = iptablesClient.Insert(IptablesNatTable, IptablesRoutingNatChain, 1, natRule...)
	if err != nil {
		return fmt.Errorf("error while adding new nat rule, error: %v", err)
	}

	i.rules[ipVersion][natRuleKey] = natRule

	return nil
}

func (i *iptablesManager) RemoveRoutingRules(pair RouterPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := Ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = Ipv6
	}

	forwardRuleKey := genKey(ForwardingFormat, pair.ID)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesFilterTable, IptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing forwarding rule, error: %v", err)
		}
	}
	delete(i.rules[ipVersion], forwardRuleKey)

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(NatFormat, pair.ID)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesNatTable, IptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing nat rule, error: %v", err)
		}
	}
	delete(i.rules[ipVersion], natRuleKey)
	return nil
}
