//go:build !android

package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func (r *family) createContainers() error {
	r.chains[chainNameRoutingFw] = r.conn.AddChain(&nftables.Chain{
		Name:  chainNameRoutingFw,
		Table: r.workTable,
	})

	prio := *nftables.ChainPriorityNATSource - 1
	r.chains[chainNameRoutingNat] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameRoutingNat,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: &prio,
		Type:     nftables.ChainTypeNAT,
	})

	r.chains[chainNameRoutingRdr] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameRoutingRdr,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})

	r.chains[chainNameManglePostrouting] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameManglePostrouting,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	})

	r.chains[chainNameManglePrerouting] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameManglePrerouting,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	})

	r.chains[chainNameMangleForward] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameMangleForward,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	})

	insertReturnTrafficRule(r.conn, r.workTable, r.chains[chainNameRoutingFw])

	r.addPostroutingRules()

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("initialize tables: %v", err)
	}

	if err := r.addMSSClampingRules(); err != nil {
		log.Errorf("failed to add MSS clamping rules: %s", err)
	}

	// Kernel routing opens both INPUT and FORWARD.
	if err := r.openInterface(true); err != nil {
		log.Errorf("failed to open interface in foreign chains: %s", err)
	}

	if err := firewalld.TrustInterface(r.wgIface.Name()); err != nil {
		log.Warnf("failed to trust interface in firewalld: %v", err)
	}

	if err := r.refreshRulesMap(); err != nil {
		log.Errorf("failed to refresh rules: %s", err)
	}

	return nil
}

// setupDataPlaneMark configures the fwmark for the data plane
func (r *family) setupDataPlaneMark() error {
	if r.chains[chainNameManglePrerouting] == nil || r.chains[chainNameManglePostrouting] == nil {
		return errors.New("no mangle chains found")
	}

	ctNew := getCtNewExprs()
	preExprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
	}
	preExprs = append(preExprs, ctNew...)
	preExprs = append(preExprs,
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(nbnet.DataPlaneMarkIn),
		},
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
	)

	preNftRule := &nftables.Rule{
		Table: r.workTable,
		Chain: r.chains[chainNameManglePrerouting],
		Exprs: preExprs,
	}
	r.conn.AddRule(preNftRule)

	postExprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyOIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
	}
	postExprs = append(postExprs, ctNew...)
	postExprs = append(postExprs,
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(nbnet.DataPlaneMarkOut),
		},
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
	)

	postNftRule := &nftables.Rule{
		Table: r.workTable,
		Chain: r.chains[chainNameManglePostrouting],
		Exprs: postExprs,
	}
	r.conn.AddRule(postNftRule)

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	return nil
}

// openInterface adds passthrough accept rules for the NetBird interface to the
// kernel's filter table and external chains so they don't drop our traffic.
// includeForward also opens the FORWARD chains (kernel routing); when false only
// INPUT is opened, which is all the userspace router needs since it never
// forwards in the kernel.
func (r *family) openInterface(includeForward bool) error {
	var merr *multierror.Error

	if err := r.acceptFilterTableRules(includeForward); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.acceptExternalChainsRules(includeForward); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("add accept rules to external chains: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) acceptFilterTableRules(includeForward bool) error {
	if r.filterTable == nil {
		return nil
	}

	fw := "iptables"

	defer func() {
		log.Debugf("Used %s to add accept input/forward rules", fw)
	}()

	// Try iptables first and fallback to nftables if iptables is not available.
	// Use the correct protocol (iptables vs ip6tables) for the address family.
	ipt, err := iptables.NewWithProtocol(r.iptablesProto())
	if err != nil {
		log.Warnf("Will use nftables to manipulate the filter table because iptables is not available: %v", err)

		fw = "nftables"
		return r.acceptFilterRulesNftables(r.filterTable, includeForward)
	}

	if err := r.acceptFilterRulesIptables(ipt, includeForward); err != nil {
		log.Warnf("iptables failed (table may be incompatible), falling back to nftables: %v", err)
		fw = "nftables"
		return r.acceptFilterRulesNftables(r.filterTable, includeForward)
	}
	return nil
}

func (r *family) acceptFilterRulesIptables(ipt *iptables.IPTables, includeForward bool) error {
	var merr *multierror.Error

	if includeForward {
		for _, rule := range r.getAcceptForwardRules() {
			if err := ipt.Insert("filter", chainNameForward, 1, rule...); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add iptables forward rule: %v", err))
			} else {
				log.Debugf("added iptables forward rule: %v", rule)
			}
		}
	}

	inputRule := r.getAcceptInputRule()
	if err := ipt.Insert("filter", chainNameInput, 1, inputRule...); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("add iptables input rule: %v", err))
	} else {
		log.Debugf("added iptables input rule: %v", inputRule)
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) getAcceptForwardRules() [][]string {
	intf := r.wgIface.Name()
	return [][]string{
		{"-i", intf, "-j", "ACCEPT"},
		{"-o", intf, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
}

func (r *family) getAcceptInputRule() []string {
	return []string{"-i", r.wgIface.Name(), "-j", "ACCEPT"}
}

// acceptFilterRulesNftables adds accept rules to the ip filter table using nftables.
// This is used when iptables is not available.
func (r *family) acceptFilterRulesNftables(table *nftables.Table, includeForward bool) error {
	intf := ifname(r.wgIface.Name())

	if includeForward {
		forwardChain := &nftables.Chain{
			Name:     chainNameForward,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		}
		r.insertForwardAcceptRules(forwardChain, intf)
	}

	inputChain := &nftables.Chain{
		Name:     chainNameInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	}
	r.insertInputAcceptRule(inputChain, intf)

	return r.conn.Flush()
}

// acceptExternalChainsRules adds accept rules to external chains (non-netbird, non-iptables tables).
// It dynamically finds chains at call time to handle chains that may have been created after startup.
func (r *family) acceptExternalChainsRules(includeForward bool) error {
	chains := r.findExternalChains()
	if len(chains) == 0 {
		return nil
	}

	intf := ifname(r.wgIface.Name())
	for _, chain := range chains {
		r.applyExternalChainAccept(chain, intf, includeForward)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush external chain rules: %w", err)
	}
	return nil
}

func (r *family) applyExternalChainAccept(chain *nftables.Chain, intf []byte, includeForward bool) {
	if chain.Hooknum == nil {
		log.Debugf("skipping external chain %s/%s: hooknum is nil", chain.Table.Name, chain.Name)
		return
	}

	log.Debugf("adding accept rules to external %s chain: %s %s/%s",
		hookName(chain.Hooknum), familyName(chain.Table.Family), chain.Table.Name, chain.Name)

	switch *chain.Hooknum {
	case *nftables.ChainHookForward:
		if includeForward {
			r.insertForwardAcceptRules(chain, intf)
		}
	case *nftables.ChainHookInput:
		r.insertInputAcceptRule(chain, intf)
	}
}

func (r *family) insertForwardAcceptRules(chain *nftables.Chain, intf []byte) {
	existing, err := r.existingNetbirdRulesInChain(chain)
	if err != nil {
		log.Warnf("skip forward accept rules in %s/%s: %v", chain.Table.Name, chain.Name, err)
		return
	}
	r.insertForwardIifRule(chain, intf, existing)
	r.insertForwardOifEstablishedRule(chain, intf, existing)
}

func (r *family) insertForwardIifRule(chain *nftables.Chain, intf []byte, existing map[string]bool) {
	if existing[userDataAcceptForwardRuleIif] {
		return
	}
	r.conn.InsertRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: intf},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		UserData: []byte(userDataAcceptForwardRuleIif),
	})
}

func (r *family) insertForwardOifEstablishedRule(chain *nftables.Chain, intf []byte, existing map[string]bool) {
	if existing[userDataAcceptForwardRuleOif] {
		return
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: intf},
	}
	r.conn.InsertRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    append(exprs, getEstablishedExprs(2)...),
		UserData: []byte(userDataAcceptForwardRuleOif),
	})
}

func (r *family) insertInputAcceptRule(chain *nftables.Chain, intf []byte) {
	existing, err := r.existingNetbirdRulesInChain(chain)
	if err != nil {
		log.Warnf("skip input accept rule in %s/%s: %v", chain.Table.Name, chain.Name, err)
		return
	}
	if existing[userDataAcceptInputRule] {
		return
	}
	r.conn.InsertRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: intf},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		UserData: []byte(userDataAcceptInputRule),
	})
}

// existingNetbirdRulesInChain returns the set of netbird-owned UserData tags present in a chain; callers must bail on error since InsertRule is additive.
func (r *family) existingNetbirdRulesInChain(chain *nftables.Chain) (map[string]bool, error) {
	rules, err := r.conn.GetRules(chain.Table, chain)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	present := map[string]bool{}
	for _, rule := range rules {
		if !isNetbirdAcceptRuleTag(rule.UserData) {
			continue
		}
		present[string(rule.UserData)] = true
	}
	return present, nil
}

func isNetbirdAcceptRuleTag(userData []byte) bool {
	switch string(userData) {
	case userDataAcceptForwardRuleIif,
		userDataAcceptForwardRuleOif,
		userDataAcceptInputRule:
		return true
	}
	return false
}

func (r *family) removeAcceptFilterRules() error {
	var merr *multierror.Error

	if err := r.removeFilterTableRules(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.removeExternalChainsRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove external chain rules: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) removeFilterTableRules() error {
	if r.filterTable == nil {
		return nil
	}

	ipt, err := iptables.NewWithProtocol(r.iptablesProto())
	if err != nil {
		log.Debugf("iptables not available, using nftables to remove filter rules: %v", err)
		return r.removeAcceptRulesFromTable(r.filterTable)
	}

	if err := r.removeAcceptFilterRulesIptables(ipt); err != nil {
		log.Debugf("iptables removal failed (table may be incompatible), falling back to nftables: %v", err)
		return r.removeAcceptRulesFromTable(r.filterTable)
	}
	return nil
}

func (r *family) removeAcceptRulesFromTable(table *nftables.Table) error {
	chains, err := r.conn.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return fmt.Errorf("list chains: %v", err)
	}

	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}

		if chain.Name != chainNameForward && chain.Name != chainNameInput {
			continue
		}

		if err := r.removeAcceptRulesFromChain(table, chain); err != nil {
			return err
		}
	}

	return r.conn.Flush()
}

func (r *family) removeAcceptRulesFromChain(table *nftables.Table, chain *nftables.Chain) error {
	rules, err := r.conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get rules from %s/%s: %v", table.Name, chain.Name, err)
	}

	for _, rule := range rules {
		if bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleIif)) ||
			bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleOif)) ||
			bytes.Equal(rule.UserData, []byte(userDataAcceptInputRule)) {
			if err := r.conn.DelRule(rule); err != nil {
				return fmt.Errorf("delete rule from %s/%s: %v", table.Name, chain.Name, err)
			}
		}
	}
	return nil
}

// removeExternalChainsRules removes our accept rules from all external chains.
// This is deterministic - it scans for chains at removal time rather than relying on saved state,
// ensuring cleanup works even after a crash or if chains changed.
func (r *family) removeExternalChainsRules() error {
	chains := r.findExternalChains()
	if len(chains) == 0 {
		return nil
	}

	var merr *multierror.Error
	for _, chain := range chains {
		if err := r.removeAcceptRulesFromChain(chain.Table, chain); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove rules from external chain %s/%s: %w", chain.Table.Name, chain.Name, err))
			continue
		}
		if err := r.conn.Flush(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("flush external chain %s/%s: %w", chain.Table.Name, chain.Name, err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// findExternalChains scans for chains from non-netbird tables that have FORWARD or INPUT hooks.
// This is used both at startup (to know where to add rules) and at cleanup (to ensure deterministic removal).
func (r *family) findExternalChains() []*nftables.Chain {
	var chains []*nftables.Chain

	families := []nftables.TableFamily{r.af.tableFamily, nftables.TableFamilyINet}

	for _, family := range families {
		allChains, err := r.conn.ListChainsOfTableFamily(family)
		if err != nil {
			log.Debugf("list chains for family %d: %v", family, err)
			continue
		}

		for _, chain := range allChains {
			if r.isExternalChain(chain) {
				chains = append(chains, chain)
			}
		}
	}

	return chains
}

func (r *family) isExternalChain(chain *nftables.Chain) bool {
	if r.workTable != nil && chain.Table.Name == r.workTable.Name {
		return false
	}

	// Skip firewalld-owned chains. Firewalld creates its chains with the
	// NFT_CHAIN_OWNER flag, so inserting rules into them returns EPERM.
	// We delegate acceptance to firewalld by trusting the interface instead.
	if chain.Table.Name == firewalldTableName {
		return false
	}

	// Skip iptables/ip6tables-managed tables (adding nft-native rules breaks iptables-save compat)
	if (chain.Table.Family == nftables.TableFamilyIPv4 || chain.Table.Family == nftables.TableFamilyIPv6) && isIptablesTable(chain.Table.Name) {
		return false
	}

	if chain.Type != nftables.ChainTypeFilter {
		return false
	}

	if chain.Hooknum == nil {
		return false
	}

	return *chain.Hooknum == *nftables.ChainHookForward || *chain.Hooknum == *nftables.ChainHookInput
}

func isIptablesTable(name string) bool {
	switch name {
	case tableNameFilter, tableNat, tableMangle, tableRaw, tableSecurity:
		return true
	}
	return false
}

func (r *family) removeAcceptFilterRulesIptables(ipt *iptables.IPTables) error {
	var merr *multierror.Error

	for _, rule := range r.getAcceptForwardRules() {
		if err := ipt.DeleteIfExists("filter", chainNameForward, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove iptables forward rule: %v", err))
		}
	}

	inputRule := r.getAcceptInputRule()
	if err := ipt.DeleteIfExists("filter", chainNameInput, inputRule...); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove iptables input rule: %v", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

// Flush rule/chain/set operations from the buffer
//
// Method also get all rules after flush and refreshes handle values in the rulesets
func (r *family) Flush() error {
	if err := r.flushWithBackoff(); err != nil {
		return err
	}

	if err := r.refreshRuleHandles(r.chainInputRules, false); err != nil {
		log.Errorf("failed to refresh rule handles ipv4 input chain: %v", err)
	}
	if err := r.refreshRuleHandles(r.chainPrerouting, true); err != nil {
		log.Errorf("failed to refresh rule handles prerouting chain: %v", err)
	}

	return nil
}

// queuePreroutingRule builds the prerouting mangle rule that marks
// redirected traffic and queues it on the connection without flushing,
// so the caller can commit it in the same transaction as the rule it
// pairs with. Returns nil when the prerouting chain is absent, in which
// case nothing is queued.
func (r *family) queuePreroutingRule(expressions []expr.Any, userData []byte) *nftables.Rule {
	if r.chainPrerouting == nil {
		log.Warn("prerouting chain is not created")
		return nil
	}

	preroutingExprs := slices.Clone(expressions)

	// interface
	preroutingExprs = append([]expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
	}, preroutingExprs...)

	// local destination and mark
	preroutingExprs = append(preroutingExprs,
		&expr.Fib{
			Register:       1,
			ResultADDRTYPE: true,
			FlagDADDR:      true,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
		},

		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkRedirected),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
	)

	return r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chainPrerouting,
		Exprs:    preroutingExprs,
		UserData: userData,
	})
}

func (r *family) createDefaultChains() (err error) {
	// chainNameInputRules
	chain := r.createChain(chainNameInputRules)
	err = r.conn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return fmt.Errorf(flushError, err)
	}
	r.chainInputRules = chain

	// netbird-acl-input-filter
	// type filter hook input priority filter; policy accept;
	chain = r.createFilterChainWithHook(chainNameInputFilter, nftables.ChainHookInput)
	r.addJumpRule(chain, r.chainInputRules.Name, expr.MetaKeyIIFNAME) // to netbird-acl-input-rules
	r.addDropExpressions(chain, expr.MetaKeyIIFNAME)
	err = r.conn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}

	// netbird-acl-forward-filter
	chainFwFilter := r.createFilterChainWithHook(chainNameForwardFilter, nftables.ChainHookForward)
	r.addJumpRulesToRtForward(chainFwFilter) // to netbird-rt-fwd
	r.addDropExpressions(chainFwFilter, expr.MetaKeyIIFNAME)

	err = r.conn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameForwardFilter, err)
		return fmt.Errorf(flushError, err)
	}

	if err := r.allowRedirectedTraffic(chainFwFilter); err != nil {
		log.Errorf("failed to allow redirected traffic: %s", err)
	}

	return nil
}

// Makes redirected traffic originally destined for the host itself (now subject to the forward filter)
// go through the input filter as well. This will enable e.g. Docker services to keep working by accessing the
// netbird peer IP.
func (r *family) allowRedirectedTraffic(chainFwFilter *nftables.Chain) error {
	r.chainPrerouting = r.chains[chainNameManglePrerouting]

	r.addFwmarkToForward(chainFwFilter)

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	return nil
}

func (r *family) addFwmarkToForward(chainFwFilter *nftables.Chain) {
	r.conn.InsertRule(&nftables.Rule{
		Table: r.workTable,
		Chain: chainFwFilter,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkRedirected),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
}

func (r *family) addJumpRulesToRtForward(chainFwFilter *nftables.Chain) {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: r.routingFwChainName,
		},
	}

	_ = r.conn.AddRule(&nftables.Rule{
		Table: r.workTable,
		Chain: chainFwFilter,
		Exprs: expressions,
	})
}

func (r *family) createChain(name string) *nftables.Chain {
	chain := &nftables.Chain{
		Name:  name,
		Table: r.workTable,
	}

	chain = r.conn.AddChain(chain)

	insertReturnTrafficRule(r.conn, r.workTable, chain)

	return chain
}

func (r *family) createFilterChainWithHook(name string, hookNum *nftables.ChainHook) *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     name,
		Table:    r.workTable,
		Hooknum:  hookNum,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	return r.conn.AddChain(chain)
}

func (r *family) addDropExpressions(chain *nftables.Chain, ifaceKey expr.MetaKey) []expr.Any {
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	_ = r.conn.AddRule(&nftables.Rule{
		Table: r.workTable,
		Chain: chain,
		Exprs: expressions,
	})
	return nil
}

func (r *family) addJumpRule(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: to,
		},
	}

	_ = r.conn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})
}

func (r *family) flushWithBackoff() (err error) {
	backoff := 4
	backoffTime := 1000 * time.Millisecond
	for i := 0; ; i++ {
		err = r.conn.Flush()
		if err != nil {
			log.Debugf("failed to flush nftables: %v", err)
			if !strings.Contains(err.Error(), "busy") {
				return
			}
			log.Error("failed to flush nftables, retrying...")
			if i == backoff-1 {
				return err
			}
			time.Sleep(backoffTime)
			backoffTime *= 2
			continue
		}
		break
	}
	return
}

func (r *family) refreshRuleHandles(chain *nftables.Chain, mangle bool) error {
	if r.workTable == nil || chain == nil {
		return nil
	}

	list, err := r.conn.GetRules(r.workTable, chain)
	if err != nil {
		return err
	}

	for _, rule := range list {
		if len(rule.UserData) == 0 {
			continue
		}
		pr, ok := r.filters[firewall.RuleID(rule.UserData)]
		if !ok {
			continue
		}
		if mangle {
			if pr.mangleRule != nil {
				*pr.mangleRule = *rule
			}
		} else {
			*pr.nftRule = *rule
		}
	}

	return nil
}
