//go:build !android

package iptables

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

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
