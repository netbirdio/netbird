//go:build !android

package iptables

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/id"
)

const (
	ipv4Nat = "netbird-rt-nat"
)

// constants needed to manage and create iptable rules
const (
	tableFilter             = "filter"
	tableNat                = "nat"
	chainPOSTROUTING        = "POSTROUTING"
	chainRTNAT              = "NETBIRD-RT-NAT"
	chainRTFWD              = "NETBIRD-RT-FWD"
	routingFinalForwardJump = "ACCEPT"
	routingFinalNatJump     = "MASQUERADE"
)

type router struct {
	ctx              context.Context
	stop             context.CancelFunc
	iptablesClient   *iptables.IPTables
	rules            map[string][]string
	wgIface          iFaceMapper
	legacyManagement bool
}

func newRouterManager(parentCtx context.Context, iptablesClient *iptables.IPTables, wgIface iFaceMapper) (*router, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	m := &router{
		ctx:            ctx,
		stop:           cancel,
		iptablesClient: iptablesClient,
		rules:          make(map[string][]string),
		wgIface:        wgIface,
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

func (r *router) AddRouteFiltering(
	source netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
) (firewall.Rule, error) {
	ruleKey := id.GenerateRouteRuleKey(source, destination, proto, sPort, dPort, direction, action)
	if _, ok := r.rules[string(ruleKey)]; ok {
		return ruleKey, nil
	}

	rule := genRouteFilteringRuleSpec(source, destination, proto, sPort, dPort, direction, action)
	if err := r.iptablesClient.Append(tableFilter, chainRTFWD, rule...); err != nil {
		return nil, fmt.Errorf("add route rule: %v", err)
	}

	r.rules[string(ruleKey)] = rule

	return ruleKey, nil
}

func (r *router) DeleteRouteRule(rule firewall.Rule) error {
	ruleKey := rule.GetRuleID()

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.Delete(tableFilter, chainRTFWD, rule...); err != nil {
			return fmt.Errorf("delete route rule: %v", err)
		}
		delete(r.rules, ruleKey)
	} else {
		log.Debugf("route rule %s not found", ruleKey)
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
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) Reset() error {
	err := r.cleanUpDefaultForwardRules()
	if err != nil {
		return err
	}
	r.rules = make(map[string][]string)
	return nil
}

func (r *router) cleanUpDefaultForwardRules() error {
	err := r.cleanJumpRules()
	if err != nil {
		return err
	}

	log.Debug("flushing routing related tables")
	for _, chain := range []string{chainRTFWD, chainRTNAT} {
		table := tableFilter
		if chain == chainRTNAT {
			table = tableNat
		}

		ok, err := r.iptablesClient.ChainExists(table, chain)
		if err != nil {
			log.Errorf("failed check chain %s, error: %v", chain, err)
			return err
		} else if ok {
			err = r.iptablesClient.ClearAndDeleteChain(table, chain)
			if err != nil {
				log.Errorf("failed cleaning chain %s, error: %v", chain, err)
				return err
			}
		}
	}

	return nil
}

func (r *router) createContainers() error {
	for _, chain := range []string{chainRTFWD, chainRTNAT} {
		if err := r.createAndSetupChain(chain); err != nil {
			return fmt.Errorf("create chain %s: %v", chain, err)
		}
	}

	if err := r.insertEstablishedRule(chainRTFWD); err != nil {
		return fmt.Errorf("insert established rule: %v", err)
	}

	return r.addJumpRules()
}

func (r *router) createAndSetupChain(chain string) error {
	table := r.getTableForChain(chain)

	if err := r.iptablesClient.NewChain(table, chain); err != nil {
		return fmt.Errorf("failed creating chain %s, error: %v", chain, err)
	}

	return nil
}

func (r *router) getTableForChain(chain string) string {
	if chain == chainRTNAT {
		return tableNat
	}
	return tableFilter
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
	rule := []string{"-j", chainRTNAT}
	err := r.iptablesClient.Insert(tableNat, chainPOSTROUTING, 1, rule...)
	if err != nil {
		return err
	}
	r.rules[ipv4Nat] = rule

	return nil
}

func (r *router) cleanJumpRules() error {
	rule, found := r.rules[ipv4Nat]
	if found {
		err := r.iptablesClient.DeleteIfExists(tableNat, chainPOSTROUTING, rule...)
		if err != nil {
			return fmt.Errorf("failed cleaning rule from chain %s, err: %v", chainPOSTROUTING, err)
		}
	}

	return nil
}

func (r *router) addNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableNat, chainRTNAT, rule...); err != nil {
			return fmt.Errorf("error while removing existing NAT rule for %s: %v", pair.Destination, err)
		}
		delete(r.rules, ruleKey)
	}

	rule := genRuleSpec(routingFinalNatJump, pair.Source, pair.Destination, r.wgIface.Name(), pair.Inverse)
	if err := r.iptablesClient.Append(tableNat, chainRTNAT, rule...); err != nil {
		return fmt.Errorf("error while appending new NAT rule for %s: %v", pair.Destination, err)
	}

	r.rules[ruleKey] = rule

	return nil
}

func (r *router) removeNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableNat, chainRTNAT, rule...); err != nil {
			return fmt.Errorf("error while removing existing nat rule for %s: %v", pair.Destination, err)
		}

		delete(r.rules, ruleKey)
	} else {
		log.Debugf("nat rule %s not found", ruleKey)
	}

	return nil
}

func genRuleSpec(jump string, source, destination netip.Prefix, intf string, inverse bool) []string {
	intdir := "-i"
	if inverse {
		intdir = "-o"
	}
	return []string{intdir, intf, "-s", source.String(), "-d", destination.String(), "-j", jump}
}

func genRouteFilteringRuleSpec(
	source netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
) []string {
	var rule []string

	if direction == firewall.RuleDirectionIN {
		rule = append(rule, "-s", source.String(), "-d", destination.String())
	} else {
		rule = append(rule, "-s", destination.String(), "-d", source.String())
	}

	if proto != firewall.ProtocolALL {
		rule = append(rule, "-p", strings.ToLower(string(proto)))

		rule = append(rule, applyPort("--sport", sPort)...)
		rule = append(rule, applyPort("--dport", dPort)...)
	}

	rule = append(rule, "-j", actionToStr(action))

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
