//go:build !android

package iptables

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func (r *family) createContainers() error {
	for _, chainInfo := range []struct {
		chain string
		table string
	}{
		{chainRTFwdIn, tableFilter},
		{chainRTFwdOut, tableFilter},
		{chainRTPre, tableMangle},
		{chainRTNAT, tableNat},
		{chainRTRdr, tableNat},
		{chainRTMSSClamp, tableMangle},
	} {
		// Fallback: clear chains that survived an unclean shutdown.
		if ok, _ := r.iptablesClient.ChainExists(chainInfo.table, chainInfo.chain); ok {
			if err := r.iptablesClient.ClearAndDeleteChain(chainInfo.table, chainInfo.chain); err != nil {
				log.Warnf("clear stale chain %s in %s: %v", chainInfo.chain, chainInfo.table, err)
			}
		}
		if err := r.iptablesClient.NewChain(chainInfo.table, chainInfo.chain); err != nil {
			return fmt.Errorf("create chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err)
		}
	}

	if err := r.insertEstablishedRule(chainRTFwdIn); err != nil {
		return fmt.Errorf("insert established rule: %w", err)
	}

	if err := r.insertEstablishedRule(chainRTFwdOut); err != nil {
		return fmt.Errorf("insert established rule: %w", err)
	}

	if err := r.addPostroutingRules(); err != nil {
		return fmt.Errorf("add static nat rules: %w", err)
	}

	if err := r.addJumpRules(); err != nil {
		return fmt.Errorf("add jump rules: %w", err)
	}

	if err := r.addMSSClampingRules(); err != nil {
		log.Errorf("failed to add MSS clamping rules: %s", err)
	}

	return nil
}

func (r *family) addJumpRules() error {
	// Jump to nat chain
	natRule := jumpRuleSpec(chainRTNAT)
	if err := r.iptablesClient.Insert(tableNat, chainPostrouting, 1, natRule...); err != nil {
		return fmt.Errorf("add nat postrouting jump rule: %w", err)
	}
	r.rules[jumpNATPost] = natRule

	// Jump to mangle prerouting chain
	preRule := jumpRuleSpec(chainRTPre)
	if err := r.iptablesClient.Insert(tableMangle, chainPrerouting, 1, preRule...); err != nil {
		return fmt.Errorf("add mangle prerouting jump rule: %w", err)
	}
	r.rules[jumpManglePre] = preRule

	// Jump to nat prerouting chain
	rdrRule := jumpRuleSpec(chainRTRdr)
	if err := r.iptablesClient.Insert(tableNat, chainPrerouting, 1, rdrRule...); err != nil {
		return fmt.Errorf("add nat prerouting jump rule: %w", err)
	}
	r.rules[jumpNATPre] = rdrRule

	return nil
}

func (r *family) setupDataPlaneMark() error {
	var merr *multierror.Error
	preRule := []string{
		"-i", r.wgIface.Name(),
		"-m", "conntrack", "--ctstate", "NEW",
		"-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#x", nbnet.DataPlaneMarkIn),
	}

	if err := r.iptablesClient.AppendUnique(tableMangle, chainPrerouting, preRule...); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("add mangle prerouting rule: %w", err))
	} else {
		r.rules[markManglePre] = preRule
	}

	postRule := []string{
		"-o", r.wgIface.Name(),
		"-m", "conntrack", "--ctstate", "NEW",
		"-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#x", nbnet.DataPlaneMarkOut),
	}

	if err := r.iptablesClient.AppendUnique(tableMangle, chainPostrouting, postRule...); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("add mangle postrouting rule: %w", err))
	} else {
		r.rules[markManglePost] = postRule
	}

	return nberrors.FormatErrorOrNil(merr)
}

// seedInitialEntries adds default rules to the entries map. Rules are
// inserted at position 1, so the order here is reversed.
//
// Existing FORWARD policy decides outbound traffic towards our
// interface. If FORWARD policy is "drop", we add an
// established/related rule to allow return traffic for inbound rules.
func (r *family) seedInitialEntries() {
	established := getConntrackEstablished()

	r.appendToEntries(chainInput, []string{"-i", r.wgIface.Name(), "-j", "DROP"})
	r.appendToEntries(chainInput, []string{"-i", r.wgIface.Name(), "-j", chainACLInput})
	r.appendToEntries(chainInput, append([]string{"-i", r.wgIface.Name()}, established...))

	r.appendToEntries(chainForward, []string{"-i", r.wgIface.Name(), "-j", "DROP"})
	r.appendToEntries(chainForward, []string{"-o", r.wgIface.Name(), "-j", chainRTFwdOut})
	r.appendToEntries(chainForward, []string{"-i", r.wgIface.Name(), "-j", chainRTFwdIn})

	// Mangle FORWARD guard: when external DNAT redirects traffic from
	// the wg interface, it traverses FORWARD instead of INPUT,
	// bypassing ACL rules. ACCEPT rules in filter FORWARD can be
	// inserted above ours. Mangle runs before filter, so these guard
	// rules enforce the ACL mark check where it cannot be overridden.
	r.appendToEntries(mangleForwardKey, []string{
		"-i", r.wgIface.Name(),
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	})
	r.appendToEntries(mangleForwardKey, []string{
		"-i", r.wgIface.Name(),
		"-m", "conntrack", "--ctstate", "DNAT",
		"-m", "mark", "!", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected),
		"-j", "DROP",
	})
}

func (r *family) seedInitialOptionalEntries() {
	r.optionalEntries[chainForward] = []entry{
		{
			spec:     []string{"-m", "mark", "--mark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected), "-j", "ACCEPT"},
			position: 2,
		},
	}
}

func (r *family) appendToEntries(chain chainKey, spec ruleSpec) {
	r.entries[chain] = append(r.entries[chain], spec)
}

func (r *family) createDefaultChains() error {
	if err := r.iptablesClient.NewChain(tableFilter, chainACLInput); err != nil {
		return fmt.Errorf("create %s chain: %w", chainACLInput, err)
	}

	for chain, rules := range r.entries {
		// mangle FORWARD guard rules are handled separately below
		if chain == mangleForwardKey {
			continue
		}
		for _, rule := range rules {
			if err := r.iptablesClient.InsertUnique(tableFilter, string(chain), 1, rule...); err != nil {
				return fmt.Errorf("insert jump rule into %s: %w", chain, err)
			}
		}
	}

	for chain, entries := range r.optionalEntries {
		for _, entry := range entries {
			if err := r.iptablesClient.InsertUnique(tableFilter, string(chain), entry.position, entry.spec...); err != nil {
				log.Errorf("failed to insert optional entry %v: %v", entry.spec, err)
				continue
			}
			r.entries[chain] = append(r.entries[chain], entry.spec)
		}
	}
	clear(r.optionalEntries)

	// Insert mangle FORWARD guard rules to prevent external DNAT bypass.
	for _, rule := range r.entries[mangleForwardKey] {
		if err := r.iptablesClient.AppendUnique(tableMangle, chainForward, rule...); err != nil {
			log.Errorf("failed to add mangle FORWARD guard rule: %v", err)
		}
	}

	return nil
}

func (r *family) cleanUpDefaultForwardRules() error {
	var merr *multierror.Error

	// cleanJumpRules removes the OUTPUT jump to NETBIRD-NAT-OUTPUT among
	// the others, so the chain below deletes cleanly instead of failing
	// with "device or resource busy".
	if err := r.cleanJumpRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("clean jump rules: %w", err))
	}

	for _, chainInfo := range []struct {
		chain string
		table string
	}{
		{chainRTFwdIn, tableFilter},
		{chainRTFwdOut, tableFilter},
		{chainRTPre, tableMangle},
		{chainRTNAT, tableNat},
		{chainRTRdr, tableNat},
		{chainNATOutput, tableNat},
		{chainRTMSSClamp, tableMangle},
	} {
		ok, err := r.iptablesClient.ChainExists(chainInfo.table, chainInfo.chain)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("check chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err))
			continue
		}
		if ok {
			if err := r.iptablesClient.ClearAndDeleteChain(chainInfo.table, chainInfo.chain); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("clear and delete chain %s in table %s: %w", chainInfo.chain, chainInfo.table, err))
			}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) cleanJumpRules() error {
	// locations maps each jump rule to the built-in table and chain it
	// was inserted into, plus the netbird chain it targets.
	locations := map[firewall.RuleID]struct{ table, chain, target string }{
		jumpNATPost:   {tableNat, chainPostrouting, chainRTNAT},
		jumpManglePre: {tableMangle, chainPrerouting, chainRTPre},
		jumpNATPre:    {tableNat, chainPrerouting, chainRTRdr},
		jumpMSSClamp:  {tableMangle, chainForward, chainRTMSSClamp},
		jumpNATOutput: {tableNat, chainOutput, chainNATOutput},
	}

	var merr *multierror.Error
	for ruleID, loc := range locations {
		rule, exists := r.rules[ruleID]
		if !exists {
			// Untracked (e.g. fresh start after an unclean shutdown with no
			// restored state): if the target chain survived, remove the stale
			// jump to it so the chain can be deleted.
			ok, err := r.iptablesClient.ChainExists(loc.table, loc.target)
			if err != nil {
				merr = multierror.Append(merr, fmt.Errorf("check chain %s in table %s: %w", loc.target, loc.table, err))
				continue
			}
			if !ok {
				continue
			}
			rule = jumpRuleSpec(loc.target)
		}
		if err := r.iptablesClient.DeleteIfExists(loc.table, loc.chain, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete rule from chain %s in table %s: %w", loc.chain, loc.table, err))
			continue
		}
		delete(r.rules, ruleID)
	}
	return nberrors.FormatErrorOrNil(merr)
}

// jumpRuleSpec builds the iptables rule spec that jumps to target. Create
// and cleanup sites share it so the installed and deleted specs cannot drift.
func jumpRuleSpec(target string) []string {
	return []string{"-j", target}
}

func (r *family) cleanAclChains() error {
	var merr *multierror.Error

	if err := r.cleanInputAclChain(); err != nil {
		merr = multierror.Append(merr, err)
	}

	for _, rule := range r.entries[mangleForwardKey] {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainForward, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete mangle %s guard rule %v: %w", chainForward, rule, err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) cleanInputAclChain() error {
	ok, err := r.iptablesClient.ChainExists(tableFilter, chainACLInput)
	if err != nil {
		return fmt.Errorf("check chain %s: %w", chainACLInput, err)
	}
	if !ok {
		return nil
	}

	var merr *multierror.Error
	for _, rule := range r.entries[chainInput] {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainInput, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete %s rule %v: %w", chainInput, rule, err))
		}
	}

	for _, rule := range r.entries[chainForward] {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chainForward, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete %s rule %v: %w", chainForward, rule, err))
		}
	}

	if err := r.iptablesClient.ClearAndDeleteChain(tableFilter, chainACLInput); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("clear and delete %s chain: %w", chainACLInput, err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) cleanupDataPlaneMark() error {
	var merr *multierror.Error
	if preRule, exists := r.rules[markManglePre]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainPrerouting, preRule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove mangle prerouting rule: %w", err))
		} else {
			delete(r.rules, markManglePre)
		}
	}

	if postRule, exists := r.rules[markManglePost]; exists {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainPostrouting, postRule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove mangle postrouting rule: %w", err))
		} else {
			delete(r.rules, markManglePost)
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
