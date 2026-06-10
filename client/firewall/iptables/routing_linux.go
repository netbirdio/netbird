//go:build !android

package iptables

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func (r *family) AddNatRule(pair firewall.RouterPair) error {
	if r.legacyManagement {
		log.Warnf("This peer is connected to a NetBird Management service with an older version. Allowing all traffic for %s", pair.Destination)
		if err := r.addLegacyRouteRule(pair); err != nil {
			return fmt.Errorf("add legacy routing rule: %w", err)
		}
	}

	if pair.Masquerade {
		if err := r.addNatRule(pair); err != nil {
			return fmt.Errorf("add nat rule: %w", err)
		}

		if err := r.addNatRule(firewall.GetInversePair(pair)); err != nil {
			return fmt.Errorf("add inverse nat rule: %w", err)
		}
	}

	r.updateState()

	return nil
}

// RemoveNatRule removes an iptables rule pair from forwarding and nat chains
func (r *family) RemoveNatRule(pair firewall.RouterPair) error {
	if pair.Masquerade {
		if err := r.removeNatRule(pair); err != nil {
			return fmt.Errorf("remove nat rule: %w", err)
		}

		if err := r.removeNatRule(firewall.GetInversePair(pair)); err != nil {
			return fmt.Errorf("remove inverse nat rule: %w", err)
		}
	}

	if err := r.removeLegacyRouteRule(pair); err != nil {
		return fmt.Errorf("remove legacy routing rule: %w", err)
	}

	r.updateState()

	return nil
}

// addLegacyRouteRule adds a legacy routing rule for mgmt servers pre route acls
func (r *family) addLegacyRouteRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.ForwardingFormat)

	if err := r.removeLegacyRouteRule(pair); err != nil {
		return err
	}

	rule := []string{"-s", pair.Source.String(), "-d", pair.Destination.String(), "-j", "ACCEPT"}
	if err := r.iptablesClient.Append(tableFilter, chainRTFwdIn, rule...); err != nil {
		return fmt.Errorf("add legacy forwarding rule %s -> %s: %w", pair.Source, pair.Destination, err)
	}

	r.rules[ruleID] = rule

	return nil
}

func (r *family) removeLegacyRouteRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.ForwardingFormat)

	if rule, exists := r.rules[ruleID]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainRTFwdIn, rule...); err != nil {
			return fmt.Errorf("remove legacy forwarding rule %s -> %s: %w", pair.Source, pair.Destination, err)
		}
		delete(r.rules, ruleID)

		if err := r.decrementSetCounter(rule); err != nil {
			return fmt.Errorf("decrement ipset counter: %w", err)
		}
	}

	return nil
}

// GetLegacyManagement returns the current legacy management mode
func (r *family) GetLegacyManagement() bool {
	return r.legacyManagement
}

// SetLegacyManagement sets the route manager to use legacy management mode
func (r *family) SetLegacyManagement(isLegacy bool) {
	r.legacyManagement = isLegacy
}

// RemoveAllLegacyRouteRules removes all legacy routing rules for mgmt servers pre route acls
func (r *family) RemoveAllLegacyRouteRules() error {
	var merr *multierror.Error
	for k, rule := range r.rules {
		if !strings.HasPrefix(string(k), firewall.ForwardingFormatPrefix) {
			continue
		}
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainRTFwdIn, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove legacy forwarding rule: %w", err))
		} else {
			delete(r.rules, k)
		}
	}

	r.updateState()

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) addPostroutingRules() error {
	// First rule for outbound masquerade
	rule1 := []string{
		"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasquerade),
		"!", "-o", "lo",
		"-j", "MASQUERADE",
	}
	if err := r.iptablesClient.Append(tableNat, chainRTNAT, rule1...); err != nil {
		return fmt.Errorf("add outbound masquerade rule: %w", err)
	}
	r.rules["static-nat-outbound"] = rule1

	// Second rule for return traffic masquerade
	rule2 := []string{
		"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasqueradeReturn),
		"-o", r.wgIface.Name(),
		"-j", "MASQUERADE",
	}
	if err := r.iptablesClient.Append(tableNat, chainRTNAT, rule2...); err != nil {
		return fmt.Errorf("add return masquerade rule: %w", err)
	}
	r.rules["static-nat-return"] = rule2

	return nil
}

// addMSSClampingRules adds MSS clamping rules to prevent fragmentation for forwarded traffic.
func (r *family) addMSSClampingRules() error {
	overhead := uint16(ipv4TCPHeaderSize)
	if r.v6 {
		overhead = ipv6TCPHeaderSize
	}
	mss := r.mtu - overhead

	// Add jump rule from FORWARD chain in mangle table to our custom chain
	jumpRule := jumpRuleSpec(chainRTMSSClamp)
	if err := r.iptablesClient.Insert(tableMangle, chainForward, 1, jumpRule...); err != nil {
		return fmt.Errorf("add jump to MSS clamp chain: %w", err)
	}
	r.rules[jumpMSSClamp] = jumpRule

	ruleOut := []string{
		"-o", r.wgIface.Name(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--set-mss", fmt.Sprintf("%d", mss),
	}
	if err := r.iptablesClient.Append(tableMangle, chainRTMSSClamp, ruleOut...); err != nil {
		return fmt.Errorf("add outbound MSS clamp rule: %w", err)
	}
	r.rules["mss-clamp-out"] = ruleOut

	return nil
}

func (r *family) insertEstablishedRule(chain string) error {
	establishedRule := getConntrackEstablished()

	err := r.iptablesClient.Insert(tableFilter, chain, 1, establishedRule...)
	if err != nil {
		return fmt.Errorf("insert established rule: %w", err)
	}

	ruleID := firewall.RuleID("established-" + chain)
	r.rules[ruleID] = establishedRule

	return nil
}

func (r *family) addNatRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.NatFormat)

	if rule, exists := r.rules[ruleID]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPre, rule...); err != nil {
			return fmt.Errorf("remove existing marking rule for %s: %w", pair.Destination, err)
		}
		delete(r.rules, ruleID)
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
	)
	sourceExp, err := r.applyNetwork("-s", pair.Source, nil)
	if err != nil {
		return fmt.Errorf("apply network -s: %w", err)
	}
	destExp, err := r.applyNetwork("-d", pair.Destination, nil)
	if err != nil {
		return fmt.Errorf("apply network -d: %w", err)
	}

	rule = append(rule, sourceExp...)
	rule = append(rule, destExp...)
	rule = append(rule,
		"-j", "MARK", "--set-mark", fmt.Sprintf("%#x", markValue),
	)

	// Ensure nat rules come first, so the mark can be overwritten.
	// Currently overwritten by the dst-type LOCAL rules for redirected traffic.
	if err := r.iptablesClient.Insert(tableMangle, chainRTPre, 1, rule...); err != nil {
		r.dropSourceMatch(rule)
		return fmt.Errorf("add marking rule for %s: %w", pair.Destination, err)
	}

	r.rules[ruleID] = rule

	return nil
}

func (r *family) removeNatRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.NatFormat)

	if rule, exists := r.rules[ruleID]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPre, rule...); err != nil {
			return fmt.Errorf("remove marking rule for %s: %w", pair.Destination, err)
		}
		delete(r.rules, ruleID)

		if err := r.decrementSetCounter(rule); err != nil {
			return fmt.Errorf("decrement ipset counter: %w", err)
		}
	} else {
		log.Debugf("marking rule %s not found", ruleID)
	}

	return nil
}
