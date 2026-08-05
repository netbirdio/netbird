//go:build !android

package iptables

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

func (r *family) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	ruleID := rule.ID()
	if _, exists := r.rules[ruleID+dnatSuffix]; exists {
		return rule, nil
	}

	toDestination := rule.TranslatedAddress.String()
	switch {
	case len(rule.TranslatedPort.Values) == 0:
		// no translated port, use original port
	case len(rule.TranslatedPort.Values) == 1:
		toDestination += fmt.Sprintf(":%d", rule.TranslatedPort.Values[0])
	case rule.TranslatedPort.IsRange && len(rule.TranslatedPort.Values) == 2:
		// need the "/originalport" suffix to avoid dnat port randomization
		toDestination += fmt.Sprintf(":%d-%d/%d", rule.TranslatedPort.Values[0], rule.TranslatedPort.Values[1], rule.DestinationPort.Values[0])
	default:
		return nil, fmt.Errorf("invalid translated port: %v", rule.TranslatedPort)
	}

	proto := strings.ToLower(string(rule.Protocol))

	rules := make(map[firewall.RuleID]ruleInfo, 3)

	// DNAT rule
	dnatRule := []string{
		"!", "-i", r.wgIface.Name(),
		"-p", proto,
		"-j", "DNAT",
		"--to-destination", toDestination,
	}
	dnatRule = append(dnatRule, applyPort("--dport", &rule.DestinationPort)...)
	rules[ruleID+dnatSuffix] = ruleInfo{
		table: tableNat,
		chain: chainRTRdr,
		rule:  dnatRule,
	}

	// SNAT rule
	snatRule := []string{
		"-o", r.wgIface.Name(),
		"-p", proto,
		"-d", rule.TranslatedAddress.String(),
		"-j", "MASQUERADE",
	}
	snatRule = append(snatRule, applyPort("--dport", &rule.TranslatedPort)...)
	rules[ruleID+snatSuffix] = ruleInfo{
		table: tableNat,
		chain: chainRTNAT,
		rule:  snatRule,
	}

	// Forward filtering rule, if fwd policy is DROP
	forwardRule := []string{
		"-o", r.wgIface.Name(),
		"-p", proto,
		"-d", rule.TranslatedAddress.String(),
		"-j", "ACCEPT",
	}
	forwardRule = append(forwardRule, applyPort("--dport", &rule.TranslatedPort)...)
	rules[ruleID+fwdSuffix] = ruleInfo{
		table: tableFilter,
		chain: chainRTFwdOut,
		rule:  forwardRule,
	}

	// Request forwarding once the rule is about to be installed, releasing
	// it if installation fails so the refcount tracks the real rules.
	if err := r.ipFwdState.RequestForwarding(); err != nil {
		return nil, err
	}

	for key, ruleInfo := range rules {
		if err := r.iptablesClient.Append(ruleInfo.table, ruleInfo.chain, ruleInfo.rule...); err != nil {
			if rollbackErr := r.rollbackRules(rules); rollbackErr != nil {
				log.Errorf("rollback failed: %v", rollbackErr)
			}
			r.releaseForwarding()
			return nil, fmt.Errorf("add rule %s: %w", key, err)
		}
		r.rules[key] = ruleInfo.rule
	}

	r.updateState()
	return rule, nil
}

func (r *family) rollbackRules(rules map[firewall.RuleID]ruleInfo) error {
	var merr *multierror.Error
	for key, ruleInfo := range rules {
		if err := r.iptablesClient.DeleteIfExists(ruleInfo.table, ruleInfo.chain, ruleInfo.rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("rollback rule %s: %w", key, err))
			// On rollback error, add to rules map for next cleanup
			r.rules[key] = ruleInfo.rule
		}
	}
	if merr != nil {
		r.updateState()
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) DeleteDNATRule(rule firewall.Rule) error {
	ruleID := rule.ID()

	var merr *multierror.Error
	var found bool
	if dnatRule, exists := r.rules[ruleID+dnatSuffix]; exists {
		found = true
		if err := r.iptablesClient.Delete(tableNat, chainRTRdr, dnatRule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete DNAT rule: %w", err))
		}
		delete(r.rules, ruleID+dnatSuffix)
	}

	if snatRule, exists := r.rules[ruleID+snatSuffix]; exists {
		found = true
		if err := r.iptablesClient.Delete(tableNat, chainRTNAT, snatRule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete SNAT rule: %w", err))
		}
		delete(r.rules, ruleID+snatSuffix)
	}

	if fwdRule, exists := r.rules[ruleID+fwdSuffix]; exists {
		found = true
		if err := r.iptablesClient.Delete(tableFilter, chainRTFwdOut, fwdRule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete forward rule: %w", err))
		}
		delete(r.rules, ruleID+fwdSuffix)
	}

	r.updateState()

	// Release once, only if the rule was present and removed.
	if merr == nil && found {
		r.releaseForwarding()
	}

	return nberrors.FormatErrorOrNil(merr)
}

// releaseForwarding drops one IP forwarding reference, logging any error.
func (r *family) releaseForwarding() {
	if err := r.ipFwdState.ReleaseForwarding(); err != nil {
		log.Errorf("release IP forwarding: %v", err)
	}
}

func (r *family) AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	ruleID := firewall.RuleID(fmt.Sprintf("inbound-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	if _, exists := r.rules[ruleID]; exists {
		return nil
	}

	dnatRule := []string{
		"-i", r.wgIface.Name(),
		"-p", strings.ToLower(protoForFamily(protocol, r.v6)),
		"--dport", strconv.Itoa(int(originalPort)),
		"-d", localAddr.String(),
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-j", "DNAT",
		"--to-destination", ":" + strconv.Itoa(int(translatedPort)),
	}

	info := ruleInfo{
		table: tableNat,
		chain: chainRTRdr,
		rule:  dnatRule,
	}

	if err := r.iptablesClient.Append(info.table, info.chain, info.rule...); err != nil {
		return fmt.Errorf("add inbound DNAT rule: %w", err)
	}
	r.rules[ruleID] = info.rule

	r.updateState()
	return nil
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (r *family) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	ruleID := firewall.RuleID(fmt.Sprintf("inbound-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	if dnatRule, exists := r.rules[ruleID]; exists {
		if err := r.iptablesClient.Delete(tableNat, chainRTRdr, dnatRule...); err != nil {
			return fmt.Errorf("delete inbound DNAT rule: %w", err)
		}
		delete(r.rules, ruleID)
	}

	r.updateState()
	return nil
}

// ensureNATOutputChain lazily creates the OUTPUT NAT chain and jump rule on first use.
func (r *family) ensureNATOutputChain() error {
	if _, exists := r.rules[jumpNATOutput]; exists {
		return nil
	}

	chainExists, err := r.iptablesClient.ChainExists(tableNat, chainNATOutput)
	if err != nil {
		return fmt.Errorf("check chain %s: %w", chainNATOutput, err)
	}
	if !chainExists {
		if err := r.iptablesClient.NewChain(tableNat, chainNATOutput); err != nil {
			return fmt.Errorf("create chain %s: %w", chainNATOutput, err)
		}
	}

	jumpRule := jumpRuleSpec(chainNATOutput)
	if err := r.iptablesClient.Insert(tableNat, chainOutput, 1, jumpRule...); err != nil {
		if !chainExists {
			if delErr := r.iptablesClient.ClearAndDeleteChain(tableNat, chainNATOutput); delErr != nil {
				log.Warnf("failed to rollback chain %s: %v", chainNATOutput, delErr)
			}
		}
		return fmt.Errorf("add OUTPUT jump rule: %w", err)
	}
	r.rules[jumpNATOutput] = jumpRule

	r.updateState()
	return nil
}

// AddOutputDNAT adds an OUTPUT chain DNAT rule for locally-generated traffic.
func (r *family) AddOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	ruleID := firewall.RuleID(fmt.Sprintf("output-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	if _, exists := r.rules[ruleID]; exists {
		return nil
	}

	if err := r.ensureNATOutputChain(); err != nil {
		return err
	}

	dnatRule := []string{
		"-p", strings.ToLower(protoForFamily(protocol, localAddr.Is6())),
		"--dport", strconv.Itoa(int(originalPort)),
		"-d", localAddr.String(),
		"-j", "DNAT",
		"--to-destination", ":" + strconv.Itoa(int(translatedPort)),
	}

	if err := r.iptablesClient.Append(tableNat, chainNATOutput, dnatRule...); err != nil {
		return fmt.Errorf("add output DNAT rule: %w", err)
	}
	r.rules[ruleID] = dnatRule

	r.updateState()
	return nil
}

// RemoveOutputDNAT removes an OUTPUT chain DNAT rule.
func (r *family) RemoveOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	ruleID := firewall.RuleID(fmt.Sprintf("output-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	if dnatRule, exists := r.rules[ruleID]; exists {
		if err := r.iptablesClient.Delete(tableNat, chainNATOutput, dnatRule...); err != nil {
			return fmt.Errorf("delete output DNAT rule: %w", err)
		}
		delete(r.rules, ruleID)
	}

	r.updateState()
	return nil
}
