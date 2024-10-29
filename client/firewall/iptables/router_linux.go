//go:build !android

package iptables

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
	"github.com/nadoo/ipset"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

// constants needed to manage and create iptable rules
const (
	tableFilter             = "filter"
	tableNat                = "nat"
	tableMangle             = "mangle"
	chainPOSTROUTING        = "POSTROUTING"
	chainPREROUTING         = "PREROUTING"
	chainRTNAT              = "NETBIRD-RT-NAT"
	chainRTFWD              = "NETBIRD-RT-FWD"
	chainRTPRE              = "NETBIRD-RT-PRE"
	routingFinalForwardJump = "ACCEPT"
	routingFinalNatJump     = "MASQUERADE"

	jumpPre  = "jump-pre"
	jumpNat  = "jump-nat"
	matchSet = "--match-set"
)

type routeFilteringRuleParams struct {
	Sources     []netip.Prefix
	Destination netip.Prefix
	Proto       firewall.Protocol
	SPort       *firewall.Port
	DPort       *firewall.Port
	Direction   firewall.RuleDirection
	Action      firewall.Action
	SetName     string
}

type routeRules map[string][]string

type ipsetCounter = refcounter.Counter[string, []netip.Prefix, struct{}]

type router struct {
	iptablesClient   *iptables.IPTables
	rules            routeRules
	ipsetCounter     *ipsetCounter
	wgIface          iFaceMapper
	legacyManagement bool

	stateManager *statemanager.Manager
}

func newRouter(iptablesClient *iptables.IPTables, wgIface iFaceMapper) (*router, error) {
	r := &router{
		iptablesClient: iptablesClient,
		rules:          make(map[string][]string),
		wgIface:        wgIface,
	}

	r.ipsetCounter = refcounter.New(
		func(name string, sources []netip.Prefix) (struct{}, error) {
			return struct{}{}, r.createIpSet(name, sources)
		},
		func(name string, _ struct{}) error {
			return r.deleteIpSet(name)
		},
	)

	if err := ipset.Init(); err != nil {
		return nil, fmt.Errorf("init ipset: %w", err)
	}

	return r, nil
}

func (r *router) init(stateManager *statemanager.Manager) error {
	r.stateManager = stateManager

	if err := r.cleanUpDefaultForwardRules(); err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	r.updateState()

	return nil
}

func (r *router) AddRouteFiltering(
	sources []netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	ruleKey := id.GenerateRouteRuleKey(sources, destination, proto, sPort, dPort, action)
	if _, ok := r.rules[string(ruleKey)]; ok {
		return ruleKey, nil
	}

	var setName string
	if len(sources) > 1 {
		setName = firewall.GenerateSetName(sources)
		if _, err := r.ipsetCounter.Increment(setName, sources); err != nil {
			return nil, fmt.Errorf("create or get ipset: %w", err)
		}
	}

	params := routeFilteringRuleParams{
		Sources:     sources,
		Destination: destination,
		Proto:       proto,
		SPort:       sPort,
		DPort:       dPort,
		Action:      action,
		SetName:     setName,
	}

	rule := genRouteFilteringRuleSpec(params)
	if err := r.iptablesClient.Append(tableFilter, chainRTFWD, rule...); err != nil {
		return nil, fmt.Errorf("add route rule: %v", err)
	}

	r.rules[string(ruleKey)] = rule

	r.updateState()

	return ruleKey, nil
}

func (r *router) DeleteRouteRule(rule firewall.Rule) error {
	ruleKey := rule.GetRuleID()

	if rule, exists := r.rules[ruleKey]; exists {
		setName := r.findSetNameInRule(rule)

		if err := r.iptablesClient.Delete(tableFilter, chainRTFWD, rule...); err != nil {
			return fmt.Errorf("delete route rule: %v", err)
		}
		delete(r.rules, ruleKey)

		if setName != "" {
			if _, err := r.ipsetCounter.Decrement(setName); err != nil {
				return fmt.Errorf("failed to remove ipset: %w", err)
			}
		}
	} else {
		log.Debugf("route rule %s not found", ruleKey)
	}

	r.updateState()

	return nil
}

func (r *router) findSetNameInRule(rule []string) string {
	for i, arg := range rule {
		if arg == "-m" && i+3 < len(rule) && rule[i+1] == "set" && rule[i+2] == matchSet {
			return rule[i+3]
		}
	}
	return ""
}

func (r *router) createIpSet(setName string, sources []netip.Prefix) error {
	if err := ipset.Create(setName, ipset.OptTimeout(0)); err != nil {
		return fmt.Errorf("create set %s: %w", setName, err)
	}

	for _, prefix := range sources {
		if err := ipset.AddPrefix(setName, prefix); err != nil {
			return fmt.Errorf("add element to set %s: %w", setName, err)
		}
	}

	return nil
}

func (r *router) deleteIpSet(setName string) error {
	if err := ipset.Destroy(setName); err != nil {
		return fmt.Errorf("destroy set %s: %w", setName, err)
	}
	return nil
}

// AddNatRule inserts an iptables rule pair into the nat chain
func (r *router) AddNatRule(pair firewall.RouterPair) error {
	if r.legacyManagement {
		log.Warnf("This peer is connected to a NetBird Management service with an older version. Allowing all traffic for %s", pair.Destination)
		if err := r.addLegacyRouteRule(pair); err != nil {
			return fmt.Errorf("add legacy routing rule: %w", err)
		}
	}

	if !pair.Masquerade {
		return nil
	}

	if err := r.addNatRule(pair); err != nil {
		return fmt.Errorf("add nat rule: %w", err)
	}

	if err := r.addNatRule(firewall.GetInversePair(pair)); err != nil {
		return fmt.Errorf("add inverse nat rule: %w", err)
	}

	r.updateState()

	return nil
}

// RemoveNatRule removes an iptables rule pair from forwarding and nat chains
func (r *router) RemoveNatRule(pair firewall.RouterPair) error {
	if err := r.removeNatRule(pair); err != nil {
		return fmt.Errorf("remove nat rule: %w", err)
	}

	if err := r.removeNatRule(firewall.GetInversePair(pair)); err != nil {
		return fmt.Errorf("remove inverse nat rule: %w", err)
	}

	if err := r.removeLegacyRouteRule(pair); err != nil {
		return fmt.Errorf("remove legacy routing rule: %w", err)
	}

	r.updateState()

	return nil
}

// addLegacyRouteRule adds a legacy routing rule for mgmt servers pre route acls
func (r *router) addLegacyRouteRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	if err := r.removeLegacyRouteRule(pair); err != nil {
		return err
	}

	rule := []string{"-s", pair.Source.String(), "-d", pair.Destination.String(), "-j", routingFinalForwardJump}
	if err := r.iptablesClient.Append(tableFilter, chainRTFWD, rule...); err != nil {
		return fmt.Errorf("add legacy forwarding rule %s -> %s: %v", pair.Source, pair.Destination, err)
	}

	r.rules[ruleKey] = rule

	return nil
}

func (r *router) removeLegacyRouteRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainRTFWD, rule...); err != nil {
			return fmt.Errorf("remove legacy forwarding rule %s -> %s: %v", pair.Source, pair.Destination, err)
		}
		delete(r.rules, ruleKey)
	} else {
		log.Debugf("legacy forwarding rule %s not found", ruleKey)
	}

	return nil
}

// GetLegacyManagement returns the current legacy management mode
func (r *router) GetLegacyManagement() bool {
	return r.legacyManagement
}

// SetLegacyManagement sets the route manager to use legacy management mode
func (r *router) SetLegacyManagement(isLegacy bool) {
	r.legacyManagement = isLegacy
}

// RemoveAllLegacyRouteRules removes all legacy routing rules for mgmt servers pre route acls
func (r *router) RemoveAllLegacyRouteRules() error {
	var merr *multierror.Error
	for k, rule := range r.rules {
		if !strings.HasPrefix(k, firewall.ForwardingFormatPrefix) {
			continue
		}
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainRTFWD, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove legacy forwarding rule: %v", err))
		} else {
			delete(r.rules, k)
		}
	}

	r.updateState()

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) Reset() error {
	var merr *multierror.Error
	if err := r.cleanUpDefaultForwardRules(); err != nil {
		merr = multierror.Append(merr, err)
	}
	r.rules = make(map[string][]string)

	if err := r.ipsetCounter.Flush(); err != nil {
		merr = multierror.Append(merr, err)
	}

	r.updateState()

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) cleanUpDefaultForwardRules() error {
	if err := r.cleanJumpRules(); err != nil {
		return fmt.Errorf("clean jump rules: %w", err)
	}

	log.Debug("flushing routing related tables")
	for _, chainInfo := range []struct {
		chain string
		table string
	}{
		{chainRTFWD, tableFilter},
		{chainRTNAT, tableNat},
		{chainRTPRE, tableMangle},
	} {
		ok, err := r.iptablesClient.ChainExists(chainInfo.table, chainInfo.chain)
		if err != nil {
			return fmt.Errorf("check chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err)
		} else if ok {
			if err = r.iptablesClient.ClearAndDeleteChain(chainInfo.table, chainInfo.chain); err != nil {
				return fmt.Errorf("clear and delete chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err)
			}
		}
	}

	return nil
}

func (r *router) createContainers() error {
	for _, chainInfo := range []struct {
		chain string
		table string
	}{
		{chainRTFWD, tableFilter},
		{chainRTPRE, tableMangle},
		{chainRTNAT, tableNat},
	} {
		if err := r.createAndSetupChain(chainInfo.chain); err != nil {
			return fmt.Errorf("create chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err)
		}
	}

	if err := r.insertEstablishedRule(chainRTFWD); err != nil {
		return fmt.Errorf("insert established rule: %w", err)
	}

	if err := r.addPostroutingRules(); err != nil {
		return fmt.Errorf("add static nat rules: %w", err)
	}

	if err := r.addJumpRules(); err != nil {
		return fmt.Errorf("add jump rules: %w", err)
	}

	return nil
}

func (r *router) addPostroutingRules() error {
	// First rule for outbound masquerade
	rule1 := []string{
		"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasquerade),
		"!", "-o", "lo",
		"-j", routingFinalNatJump,
	}
	if err := r.iptablesClient.Append(tableNat, chainRTNAT, rule1...); err != nil {
		return fmt.Errorf("add outbound masquerade rule: %v", err)
	}
	r.rules["static-nat-outbound"] = rule1

	// Second rule for return traffic masquerade
	rule2 := []string{
		"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasqueradeReturn),
		"-o", r.wgIface.Name(),
		"-j", routingFinalNatJump,
	}
	if err := r.iptablesClient.Append(tableNat, chainRTNAT, rule2...); err != nil {
		return fmt.Errorf("add return masquerade rule: %v", err)
	}
	r.rules["static-nat-return"] = rule2

	return nil
}

func (r *router) createAndSetupChain(chain string) error {
	table := r.getTableForChain(chain)

	if err := r.iptablesClient.NewChain(table, chain); err != nil {
		return fmt.Errorf("failed creating chain %s, error: %v", chain, err)
	}

	return nil
}

func (r *router) getTableForChain(chain string) string {
	switch chain {
	case chainRTNAT:
		return tableNat
	case chainRTPRE:
		return tableMangle
	default:
		return tableFilter
	}
}

func (r *router) insertEstablishedRule(chain string) error {
	establishedRule := getConntrackEstablished()

	err := r.iptablesClient.Insert(tableFilter, chain, 1, establishedRule...)
	if err != nil {
		return fmt.Errorf("failed to insert established rule: %v", err)
	}

	ruleKey := "established-" + chain
	r.rules[ruleKey] = establishedRule

	return nil
}

func (r *router) addJumpRules() error {
	// Jump to NAT chain
	natRule := []string{"-j", chainRTNAT}
	if err := r.iptablesClient.Insert(tableNat, chainPOSTROUTING, 1, natRule...); err != nil {
		return fmt.Errorf("add nat jump rule: %v", err)
	}
	r.rules[jumpNat] = natRule

	// Jump to prerouting chain
	preRule := []string{"-j", chainRTPRE}
	if err := r.iptablesClient.Insert(tableMangle, chainPREROUTING, 1, preRule...); err != nil {
		return fmt.Errorf("add prerouting jump rule: %v", err)
	}
	r.rules[jumpPre] = preRule

	return nil
}

func (r *router) cleanJumpRules() error {
	for _, ruleKey := range []string{jumpNat, jumpPre} {
		if rule, exists := r.rules[ruleKey]; exists {
			table := tableNat
			chain := chainPOSTROUTING
			if ruleKey == jumpPre {
				table = tableMangle
				chain = chainPREROUTING
			}

			if err := r.iptablesClient.DeleteIfExists(table, chain, rule...); err != nil {
				return fmt.Errorf("delete rule from chain %s in table %s, err: %v", chain, table, err)
			}
			delete(r.rules, ruleKey)
		}
	}
	return nil
}

func (r *router) addNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPRE, rule...); err != nil {
			return fmt.Errorf("error while removing existing marking rule for %s: %v", pair.Destination, err)
		}
		delete(r.rules, ruleKey)
	}

	markValue := nbnet.PreroutingFwmarkMasquerade
	if pair.Inverse {
		markValue = nbnet.PreroutingFwmarkMasqueradeReturn
	}

	rule := []string{"-i", r.wgIface.Name()}
	if pair.Inverse {
		rule = []string{"!", "-i", r.wgIface.Name()}
	}

	rule = append(rule,
		"-m", "conntrack",
		"--ctstate", "NEW",
		"-s", pair.Source.String(),
		"-d", pair.Destination.String(),
		"-j", "MARK", "--set-mark", fmt.Sprintf("%#x", markValue),
	)

	if err := r.iptablesClient.Append(tableMangle, chainRTPRE, rule...); err != nil {
		return fmt.Errorf("error while adding marking rule for %s: %v", pair.Destination, err)
	}

	r.rules[ruleKey] = rule
	return nil
}

func (r *router) removeNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPRE, rule...); err != nil {
			return fmt.Errorf("error while removing marking rule for %s: %v", pair.Destination, err)
		}
		delete(r.rules, ruleKey)
	} else {
		log.Debugf("marking rule %s not found", ruleKey)
	}

	return nil
}

func (r *router) updateState() {
	if r.stateManager == nil {
		return
	}

	var currentState *ShutdownState
	if existing := r.stateManager.GetState(currentState); existing != nil {
		if existingState, ok := existing.(*ShutdownState); ok {
			currentState = existingState
		}
	}
	if currentState == nil {
		currentState = &ShutdownState{}
	}

	currentState.Lock()
	defer currentState.Unlock()

	currentState.RouteRules = r.rules
	currentState.RouteIPsetCounter = r.ipsetCounter

	if err := r.stateManager.UpdateState(currentState); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}

func genRouteFilteringRuleSpec(params routeFilteringRuleParams) []string {
	var rule []string

	if params.SetName != "" {
		rule = append(rule, "-m", "set", matchSet, params.SetName, "src")
	} else if len(params.Sources) > 0 {
		source := params.Sources[0]
		rule = append(rule, "-s", source.String())
	}

	rule = append(rule, "-d", params.Destination.String())

	if params.Proto != firewall.ProtocolALL {
		rule = append(rule, "-p", strings.ToLower(string(params.Proto)))
		rule = append(rule, applyPort("--sport", params.SPort)...)
		rule = append(rule, applyPort("--dport", params.DPort)...)
	}

	rule = append(rule, "-j", actionToStr(params.Action))

	return rule
}

func applyPort(flag string, port *firewall.Port) []string {
	if port == nil {
		return nil
	}

	if port.IsRange && len(port.Values) == 2 {
		return []string{flag, fmt.Sprintf("%d:%d", port.Values[0], port.Values[1])}
	}

	if len(port.Values) > 1 {
		portList := make([]string, len(port.Values))
		for i, p := range port.Values {
			portList[i] = strconv.Itoa(p)
		}
		return []string{"-m", "multiport", flag, strings.Join(portList, ",")}
	}

	return []string{flag, strconv.Itoa(port.Values[0])}
}
