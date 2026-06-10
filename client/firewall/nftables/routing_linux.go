//go:build !android

package nftables

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func (r *family) AddNatRule(pair firewall.RouterPair) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	if r.legacyManagement {
		log.Warnf("This peer is connected to a NetBird Management service with an older version. Allowing all traffic for %s", pair.Destination)
		if err := r.addLegacyRouteRule(pair); err != nil {
			r.rollbackRules(pair)
			return fmt.Errorf("add legacy routing rule: %w", err)
		}
	}

	if pair.Masquerade {
		if err := r.addNatRule(pair); err != nil {
			r.rollbackRules(pair)
			return fmt.Errorf("add nat rule: %w", err)
		}

		if err := r.addNatRule(firewall.GetInversePair(pair)); err != nil {
			r.rollbackRules(pair)
			return fmt.Errorf("add inverse nat rule: %w", err)
		}
	}

	if err := r.conn.Flush(); err != nil {
		r.rollbackRules(pair)
		return fmt.Errorf("insert rules for %s: %w", pair.Destination, err)
	}

	return nil
}

// rollbackRules cleans up unflushed rules and their set counters after a flush failure.
func (r *family) rollbackRules(pair firewall.RouterPair) {
	keys := []firewall.RuleID{
		pair.GenKey(firewall.ForwardingFormat),
		pair.GenKey(firewall.PreroutingFormat),
		firewall.GetInversePair(pair).GenKey(firewall.PreroutingFormat),
	}
	for _, key := range keys {
		rule, ok := r.rules[key]
		if !ok {
			continue
		}
		if err := r.decrementSetCounter(rule); err != nil {
			log.Warnf("rollback set counter for %s: %v", key, err)
		}
		delete(r.rules, key)
	}
}

// addNatRule inserts a nftables rule to the conn client flush queue
func (r *family) addNatRule(pair firewall.RouterPair) error {
	sourceExp, err := r.applyNetwork(pair.Source, nil, true)
	if err != nil {
		return fmt.Errorf("apply source: %w", err)
	}

	destExp, err := r.applyNetwork(pair.Destination, nil, false)
	if err != nil {
		r.dropNetworkMatch(sourceExp)
		return fmt.Errorf("apply destination: %w", err)
	}

	op := expr.CmpOpEq
	if pair.Inverse {
		op = expr.CmpOpNeq
	}

	exprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       op,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
	}
	// We only care about NEW connections to mark them and later identify them in the postrouting chain for masquerading.
	// Masquerading will take care of the conntrack state, which means we won't need to mark established connections.
	exprs = append(exprs, getCtNewExprs()...)

	exprs = append(exprs, sourceExp...)
	exprs = append(exprs, destExp...)

	var markValue uint32 = nbnet.PreroutingFwmarkMasquerade
	if pair.Inverse {
		markValue = nbnet.PreroutingFwmarkMasqueradeReturn
	}

	exprs = append(exprs,
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(markValue),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	)

	ruleID := pair.GenKey(firewall.PreroutingFormat)

	if _, exists := r.rules[ruleID]; exists {
		if err := r.removeNatRule(pair); err != nil {
			r.dropNetworkMatch(sourceExp)
			r.dropNetworkMatch(destExp)
			return fmt.Errorf("remove prerouting rule: %w", err)
		}
	}

	// Ensure nat rules come first, so the mark can be overwritten.
	// Currently overwritten by the dst-type LOCAL rules for redirected traffic.
	r.rules[ruleID] = r.conn.InsertRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameManglePrerouting],
		Exprs:    exprs,
		UserData: []byte(ruleID),
	})

	return nil
}

func (r *family) addPostroutingRules() {
	// First masquerade rule for traffic coming in from WireGuard interface
	exprs := []expr.Any{
		// Match on the first fwmark
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkMasquerade),
		},

		// We need to exclude the loopback interface as this changes the ebpf proxy port
		&expr.Meta{
			Key:      expr.MetaKeyOIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     ifname("lo"),
		},
		&expr.Counter{},
		&expr.Masq{},
	}

	r.conn.AddRule(&nftables.Rule{
		Table: r.workTable,
		Chain: r.chains[chainNameRoutingNat],
		Exprs: exprs,
	})

	// Second masquerade rule for traffic going out through WireGuard interface
	exprs2 := []expr.Any{
		// Match on the second fwmark
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkMasqueradeReturn),
		},

		// Match WireGuard interface
		&expr.Meta{
			Key:      expr.MetaKeyOIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Counter{},
		&expr.Masq{},
	}

	r.conn.AddRule(&nftables.Rule{
		Table: r.workTable,
		Chain: r.chains[chainNameRoutingNat],
		Exprs: exprs2,
	})
}

// addMSSClampingRules adds MSS clamping rules to prevent fragmentation for forwarded traffic.
func (r *family) addMSSClampingRules() error {
	overhead := uint16(ipv4TCPHeaderSize)
	if r.af.tableFamily == nftables.TableFamilyIPv6 {
		overhead = ipv6TCPHeaderSize
	}
	if r.mtu <= overhead {
		log.Debugf("MTU %d too small for MSS clamping (overhead %d), skipping", r.mtu, overhead)
		return nil
	}
	mss := r.mtu - overhead

	exprsOut := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyOIFNAME,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            1,
			Mask:           []byte{0x02},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0x00},
		},
		&expr.Counter{},
		&expr.Exthdr{
			DestRegister: 1,
			Type:         2,
			Offset:       2,
			Len:          2,
			Op:           expr.ExthdrOpTcpopt,
		},
		&expr.Cmp{
			Op:       expr.CmpOpGt,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(uint16(mss)),
		},
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(uint16(mss)),
		},
		&expr.Exthdr{
			SourceRegister: 1,
			Type:           2,
			Offset:         2,
			Len:            2,
			Op:             expr.ExthdrOpTcpopt,
		},
	}

	r.conn.AddRule(&nftables.Rule{
		Table: r.workTable,
		Chain: r.chains[chainNameMangleForward],
		Exprs: exprsOut,
	})

	return r.conn.Flush()
}

func (r *family) addLegacyRouteRule(pair firewall.RouterPair) error {
	sourceExp, err := r.applyNetwork(pair.Source, nil, true)
	if err != nil {
		return fmt.Errorf("apply source: %w", err)
	}

	destExp, err := r.applyNetwork(pair.Destination, nil, false)
	if err != nil {
		r.dropNetworkMatch(sourceExp)
		return fmt.Errorf("apply destination: %w", err)
	}

	var exprs []expr.Any
	exprs = append(exprs, sourceExp...)
	exprs = append(exprs, destExp...)
	exprs = append(exprs,
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	ruleID := pair.GenKey(firewall.ForwardingFormat)

	if _, exists := r.rules[ruleID]; exists {
		if err := r.removeLegacyRouteRule(pair); err != nil {
			r.dropNetworkMatch(sourceExp)
			r.dropNetworkMatch(destExp)
			return fmt.Errorf("remove legacy routing rule: %w", err)
		}
	}

	r.rules[ruleID] = r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingFw],
		Exprs:    exprs,
		UserData: []byte(ruleID),
	})
	return nil
}

// removeLegacyRouteRule removes a legacy routing rule for mgmt servers pre route acls
func (r *family) removeLegacyRouteRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.ForwardingFormat)

	rule, exists := r.rules[ruleID]
	if !exists {
		return nil
	}

	return r.deleteLegacyRuleEntry(ruleID, rule)
}

// deleteLegacyRuleEntry removes one legacy forwarding rule and drops its
// ipset references. It also clears stale entries that never got a handle.
func (r *family) deleteLegacyRuleEntry(ruleID firewall.RuleID, rule *nftables.Rule) error {
	if rule.Handle == 0 {
		log.Warnf("legacy forwarding rule %s has no handle, removing stale entry", ruleID)
		if err := r.decrementSetCounter(rule); err != nil {
			log.Warnf("decrement set counter for stale rule %s: %v", ruleID, err)
		}
		delete(r.rules, ruleID)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("remove legacy forwarding rule %s: %w", ruleID, err)
	}

	delete(r.rules, ruleID)

	if err := r.decrementSetCounter(rule); err != nil {
		return fmt.Errorf("decrement set counter: %w", err)
	}

	return nil
}

// GetLegacyManagement returns the route manager's legacy management mode
func (r *family) GetLegacyManagement() bool {
	return r.legacyManagement
}

// SetLegacyManagement sets the route manager to use legacy management mode
func (r *family) SetLegacyManagement(isLegacy bool) {
	r.legacyManagement = isLegacy
}

// RemoveAllLegacyRouteRules removes all legacy routing rules for mgmt servers pre route acls
func (r *family) RemoveAllLegacyRouteRules() error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	var merr *multierror.Error
	for k, rule := range r.rules {
		if !strings.HasPrefix(string(k), firewall.ForwardingFormatPrefix) {
			continue
		}
		if err := r.deleteLegacyRuleEntry(k, rule); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) removeNatPreroutingRules() error {
	table := &nftables.Table{
		Name:   tableNat,
		Family: r.af.tableFamily,
	}
	chain := &nftables.Chain{
		Name:     chainNameNatPrerouting,
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	}
	rules, err := r.conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get rules from nat table: %w", err)
	}

	var merr *multierror.Error

	// Delete rules that have our UserData suffix
	for _, rule := range rules {
		if len(rule.UserData) == 0 || !strings.HasSuffix(string(rule.UserData), string(dnatSuffix)) {
			continue
		}
		if err := r.conn.DelRule(rule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete rule %s: %w", rule.UserData, err))
		}
	}

	if err := r.conn.Flush(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf(flushError, err))
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) RemoveNatRule(pair firewall.RouterPair) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	var merr *multierror.Error

	if pair.Masquerade {
		if err := r.removeNatRule(pair); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove prerouting rule: %w", err))
		}

		if err := r.removeNatRule(firewall.GetInversePair(pair)); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove inverse prerouting rule: %w", err))
		}
	}

	if err := r.removeLegacyRouteRule(pair); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove legacy routing rule: %w", err))
	}

	// Set counters are decremented in the sub-methods above before flush. If flush fails,
	// counters will be off until the next successful removal or refresh cycle.
	if err := r.conn.Flush(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("flush remove nat rules %s: %w", pair.Destination, err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) removeNatRule(pair firewall.RouterPair) error {
	ruleID := pair.GenKey(firewall.PreroutingFormat)

	rule, exists := r.rules[ruleID]
	if !exists {
		log.Debugf("prerouting rule %s not found", ruleID)
		return nil
	}

	if rule.Handle == 0 {
		log.Warnf("prerouting rule %s has no handle, removing stale entry", ruleID)
		if err := r.decrementSetCounter(rule); err != nil {
			log.Warnf("decrement set counter for stale rule %s: %v", ruleID, err)
		}
		delete(r.rules, ruleID)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("remove prerouting rule %s -> %s: %w", pair.Source, pair.Destination, err)
	}

	log.Debugf("removed prerouting rule %s -> %s", pair.Source, pair.Destination)

	delete(r.rules, ruleID)

	if err := r.decrementSetCounter(rule); err != nil {
		return fmt.Errorf("decrement set counter: %w", err)
	}

	return nil
}
