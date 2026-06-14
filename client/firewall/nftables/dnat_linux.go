//go:build !android

package nftables

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
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

	protoNum, err := r.af.protoNum(rule.Protocol)
	if err != nil {
		return nil, fmt.Errorf("convert protocol to number: %w", err)
	}

	// Request forwarding once the rule is about to be installed, releasing
	// it if a later step fails so the refcount tracks the real rules.
	if err := r.ipFwdState.RequestForwarding(); err != nil {
		return nil, err
	}

	if err := r.addDnatRedirect(rule, protoNum, ruleID); err != nil {
		r.releaseForwarding()
		return nil, err
	}

	if err := r.addDnatMasq(rule, protoNum, ruleID); err != nil {
		r.releaseForwarding()
		delete(r.rules, ruleID+dnatSuffix)
		return nil, err
	}

	// Unlike iptables, there's no point in adding "out" rules in the forward chain here as our policy is ACCEPT.
	// To overcome DROP policies in other chains, we'd have to add rules to the chains there.
	// We also cannot just add "oif <iface> accept" there and filter in our own table as we don't know what is supposed to be allowed.
	// TODO: find chains with drop policies and add rules there

	if err := r.conn.Flush(); err != nil {
		r.releaseForwarding()
		return nil, fmt.Errorf("flush rules: %w", err)
	}

	return &rule, nil
}

func (r *family) addDnatRedirect(rule firewall.ForwardRule, protoNum uint8, ruleID firewall.RuleID) error {
	dnatExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protoNum},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
	}
	portExprs, err := r.applyPort(&rule.DestinationPort, false)
	if err != nil {
		return fmt.Errorf("apply destination port: %w", err)
	}
	dnatExprs = append(dnatExprs, portExprs...)

	// shifted translated port is not supported in nftables, so we hand this over to xtables
	if rule.TranslatedPort.IsRange && len(rule.TranslatedPort.Values) == 2 {
		if rule.TranslatedPort.Values[0] != rule.DestinationPort.Values[0] ||
			rule.TranslatedPort.Values[1] != rule.DestinationPort.Values[1] {
			return r.addXTablesRedirect(dnatExprs, ruleID, rule)
		}
	}

	additionalExprs, regProtoMin, regProtoMax, err := r.handleTranslatedPort(rule)
	if err != nil {
		return err
	}
	dnatExprs = append(dnatExprs, additionalExprs...)

	dnatExprs = append(dnatExprs,
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(r.af.tableFamily),
			RegAddrMin:  1,
			RegProtoMin: regProtoMin,
			RegProtoMax: regProtoMax,
		},
	)

	dnatRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingRdr],
		Exprs:    dnatExprs,
		UserData: []byte(ruleID + dnatSuffix),
	}
	r.conn.AddRule(dnatRule)
	r.rules[ruleID+dnatSuffix] = dnatRule

	return nil
}

func (r *family) handleTranslatedPort(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
	switch {
	case rule.TranslatedPort.IsRange && len(rule.TranslatedPort.Values) == 2:
		return r.handlePortRange(rule)
	case len(rule.TranslatedPort.Values) == 0:
		return r.handleAddressOnly(rule)
	case len(rule.TranslatedPort.Values) == 1:
		return r.handleSinglePort(rule)
	default:
		return nil, 0, 0, fmt.Errorf("invalid translated port: %v", rule.TranslatedPort)
	}
}

func (r *family) handlePortRange(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
	exprs := []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(rule.TranslatedPort.Values[0]),
		},
		&expr.Immediate{
			Register: 3,
			Data:     binaryutil.BigEndian.PutUint16(rule.TranslatedPort.Values[1]),
		},
	}
	return exprs, 2, 3, nil
}

func (r *family) handleAddressOnly(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
	exprs := []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
	}
	return exprs, 0, 0, nil
}

func (r *family) handleSinglePort(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
	exprs := []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(rule.TranslatedPort.Values[0]),
		},
	}
	return exprs, 2, 0, nil
}

func (r *family) addXTablesRedirect(dnatExprs []expr.Any, ruleID firewall.RuleID, rule firewall.ForwardRule) error {
	dnatExprs = append(dnatExprs,
		&expr.Counter{},
		&expr.Target{
			Name: "DNAT",
			Rev:  2,
			Info: &xt.NatRange2{
				NatRange: xt.NatRange{
					Flags:   uint(xt.NatRangeMapIPs | xt.NatRangeProtoSpecified | xt.NatRangeProtoOffset),
					MinIP:   rule.TranslatedAddress.AsSlice(),
					MaxIP:   rule.TranslatedAddress.AsSlice(),
					MinPort: rule.TranslatedPort.Values[0],
					MaxPort: rule.TranslatedPort.Values[1],
				},
				BasePort: rule.DestinationPort.Values[0],
			},
		},
	)

	natTable := &nftables.Table{
		Name:   tableNat,
		Family: r.af.tableFamily,
	}
	dnatRule := &nftables.Rule{
		Table: natTable,
		Chain: &nftables.Chain{
			Name:     chainNameNatPrerouting,
			Table:    natTable,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityNATDest,
		},
		Exprs:    dnatExprs,
		UserData: []byte(ruleID + dnatSuffix),
	}
	r.conn.AddRule(dnatRule)
	r.rules[ruleID+dnatSuffix] = dnatRule

	return nil
}

func (r *family) addDnatMasq(rule firewall.ForwardRule, protoNum uint8, ruleID firewall.RuleID) error {
	portExprs, err := r.applyPort(&rule.TranslatedPort, false)
	if err != nil {
		return fmt.Errorf("apply translated port: %w", err)
	}

	masqExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protoNum},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       r.af.dstAddrOffset,
			Len:          r.af.addrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
	}

	masqExprs = append(masqExprs, portExprs...)
	masqExprs = append(masqExprs, &expr.Masq{})

	masqRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingNat],
		Exprs:    masqExprs,
		UserData: []byte(ruleID + snatSuffix),
	}
	r.conn.AddRule(masqRule)
	r.rules[ruleID+snatSuffix] = masqRule

	return nil
}

func (r *family) DeleteDNATRule(rule firewall.Rule) error {
	ruleID := rule.ID()

	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	var merr *multierror.Error
	var needsFlush bool
	var found bool

	if dnatRule, exists := r.rules[ruleID+dnatSuffix]; exists {
		found = true
		if dnatRule.Handle == 0 {
			log.Warnf("dnat rule %s has no handle, removing stale entry", ruleID+dnatSuffix)
			delete(r.rules, ruleID+dnatSuffix)
		} else if err := r.conn.DelRule(dnatRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete dnat rule: %w", err))
		} else {
			needsFlush = true
		}
	}

	if masqRule, exists := r.rules[ruleID+snatSuffix]; exists {
		found = true
		if masqRule.Handle == 0 {
			log.Warnf("snat rule %s has no handle, removing stale entry", ruleID+snatSuffix)
			delete(r.rules, ruleID+snatSuffix)
		} else if err := r.conn.DelRule(masqRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete snat rule: %w", err))
		} else {
			needsFlush = true
		}
	}

	if needsFlush {
		if err := r.conn.Flush(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf(flushError, err))
		}
	}

	if merr != nil {
		return nberrors.FormatErrorOrNil(merr)
	}

	delete(r.rules, ruleID+dnatSuffix)
	delete(r.rules, ruleID+snatSuffix)

	// Release once, only if the rule was present and removed.
	if found {
		r.releaseForwarding()
	}

	return nil
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

	protoNum, err := r.af.protoNum(protocol)
	if err != nil {
		return fmt.Errorf("convert protocol to number: %w", err)
	}

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.wgIface.Name()),
		},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     []byte{protoNum},
		},
		&expr.Payload{
			DestRegister: 3,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 3,
			Data:     binaryutil.BigEndian.PutUint16(originalPort),
		},
	}

	bits := 32
	if localAddr.Is6() {
		bits = 128
	}
	exprs = append(exprs, prefixMatchExprs(r.af, netip.PrefixFrom(localAddr, bits), false)...)

	exprs = append(exprs,
		&expr.Immediate{
			Register: 1,
			Data:     localAddr.AsSlice(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(translatedPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(r.af.tableFamily),
			RegAddrMin:  1,
			RegProtoMin: 2,
			RegProtoMax: 0,
		},
	)

	dnatRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingRdr],
		Exprs:    exprs,
		UserData: []byte(ruleID),
	}
	r.conn.AddRule(dnatRule)

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("add inbound DNAT rule: %w", err)
	}

	r.rules[ruleID] = dnatRule

	return nil
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (r *family) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	ruleID := firewall.RuleID(fmt.Sprintf("inbound-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	rule, exists := r.rules[ruleID]
	if !exists {
		return nil
	}

	if rule.Handle == 0 {
		log.Warnf("inbound DNAT rule %s has no handle, removing stale entry", ruleID)
		delete(r.rules, ruleID)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("delete inbound DNAT rule %s: %w", ruleID, err)
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush delete inbound DNAT rule: %w", err)
	}
	delete(r.rules, ruleID)

	return nil
}

// ensureNATOutputChain lazily creates the OUTPUT NAT chain on first use.
func (r *family) ensureNATOutputChain() error {
	if _, exists := r.chains[chainNameNATOutput]; exists {
		return nil
	}

	r.chains[chainNameNATOutput] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameNATOutput,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})

	if err := r.conn.Flush(); err != nil {
		delete(r.chains, chainNameNATOutput)
		return fmt.Errorf("create NAT output chain: %w", err)
	}
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

	protoNum, err := r.af.protoNum(protocol)
	if err != nil {
		return fmt.Errorf("convert protocol to number: %w", err)
	}

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protoNum},
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(originalPort),
		},
	}

	bits := 32
	if localAddr.Is6() {
		bits = 128
	}
	exprs = append(exprs, prefixMatchExprs(r.af, netip.PrefixFrom(localAddr, bits), false)...)

	exprs = append(exprs,
		&expr.Immediate{
			Register: 1,
			Data:     localAddr.AsSlice(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(translatedPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(r.af.tableFamily),
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	)

	dnatRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameNATOutput],
		Exprs:    exprs,
		UserData: []byte(ruleID),
	}
	r.conn.AddRule(dnatRule)

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("add output DNAT rule: %w", err)
	}

	r.rules[ruleID] = dnatRule

	return nil
}

// RemoveOutputDNAT removes an OUTPUT chain DNAT rule.
func (r *family) RemoveOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	ruleID := firewall.RuleID(fmt.Sprintf("output-dnat-%s-%s-%d-%d", localAddr.String(), protocol, originalPort, translatedPort))

	rule, exists := r.rules[ruleID]
	if !exists {
		return nil
	}

	if rule.Handle == 0 {
		log.Warnf("output DNAT rule %s has no handle, removing stale entry", ruleID)
		delete(r.rules, ruleID)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("delete output DNAT rule %s: %w", ruleID, err)
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush delete output DNAT rule: %w", err)
	}
	delete(r.rules, ruleID)

	return nil
}
