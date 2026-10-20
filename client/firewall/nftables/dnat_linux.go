//go:build !android

package nftables

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

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
