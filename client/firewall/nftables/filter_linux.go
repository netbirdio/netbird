//go:build !android

package nftables

import (
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
)

// AddFilterRule installs one nftables packet-filter rule. With
// destination empty the rule goes to the peer ACL input chain plus a
// paired prerouting mangle rule for the redirect mark. With
// destination set (prefix or named set) it goes to the route ACL
// forward chain. Multi-source rules collapse to one nftables rule
// backed by the shared refcounted hash:net set.
func (r *family) AddFilterRule(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	isRoute := !destination.IsZero()

	ruleID := nbid.GenerateRuleID(sources, destination, proto, sPort, dPort, action)
	if existing, ok := r.filters[ruleID]; ok {
		return existing, nil
	}

	srcExprs, err := r.applyNetwork(sourceNetwork(sources), sources, true)
	if err != nil {
		return nil, fmt.Errorf("apply source: %w", err)
	}

	var exprs []expr.Any
	if isRoute {
		exprs, err = r.buildRouteFilterExprs(srcExprs, destination, proto, sPort, dPort)
	} else {
		exprs, err = r.buildPeerFilterExprs(srcExprs, proto, sPort, dPort)
	}
	if err != nil {
		r.dropNetworkMatch(srcExprs)
		return nil, err
	}

	mainExprs := slices.Clone(exprs)
	verdict := expr.VerdictAccept
	if action == firewall.ActionDrop {
		verdict = expr.VerdictDrop
	}
	mainExprs = append(mainExprs, &expr.Verdict{Kind: verdict})

	chain := r.chainInputRules
	if isRoute {
		chain = r.chains[chainNameRoutingFw]
	}

	userData := []byte(ruleID)
	nftRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    chain,
		Exprs:    mainExprs,
		UserData: userData,
	}
	if action == firewall.ActionDrop {
		nftRule = r.conn.InsertRule(nftRule)
	} else {
		nftRule = r.conn.AddRule(nftRule)
	}
	if err := r.conn.Flush(); err != nil {
		r.dropNetworkMatch(exprs)
		return nil, fmt.Errorf(flushError, err)
	}

	rule := &Rule{
		nftRule: nftRule,
		sources: sources,
		id:      ruleID,
	}
	if !isRoute {
		rule.mangleRule = r.createPreroutingRule(exprs, userData)
	}
	r.filters[ruleID] = rule

	log.Debugf("added filter rule: sources=%v, destination=%v, proto=%v, sPort=%v, dPort=%v, action=%v",
		sources, destination, proto, sPort, dPort, action)
	return rule, nil
}

// buildPeerFilterExprs assembles the input-chain (peer ACL) match: the
// IP-header protocol byte read via Payload, then source, then ports
// (no counter), matching the historical peer shape so per-rule kernel
// state is identical to pre-unification.
func (r *family) buildPeerFilterExprs(
	srcExprs []expr.Any,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
) ([]expr.Any, error) {
	var exprs []expr.Any

	if proto != firewall.ProtocolALL {
		protoNum, err := r.af.protoNum(proto)
		if err != nil {
			return nil, fmt.Errorf("convert protocol to number: %w", err)
		}
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       r.af.protoOffset,
				Len:          1,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum}},
		)
	}
	exprs = append(exprs, srcExprs...)
	exprs = append(exprs, applyPort(sPort, true)...)
	exprs = append(exprs, applyPort(dPort, false)...)
	return exprs, nil
}

// buildRouteFilterExprs assembles the forward-chain (route ACL) match:
// source, then destination, then optional proto/ports, then a counter.
func (r *family) buildRouteFilterExprs(
	srcExprs []expr.Any,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
) ([]expr.Any, error) {
	exprs := append([]expr.Any{}, srcExprs...)

	destExprs, err := r.applyNetwork(destination, nil, false)
	if err != nil {
		return nil, fmt.Errorf("apply destination: %w", err)
	}
	exprs = append(exprs, destExprs...)

	if proto != firewall.ProtocolALL {
		protoNum, err := r.af.protoNum(proto)
		if err != nil {
			r.dropNetworkMatch(destExprs)
			return nil, fmt.Errorf("convert protocol to number: %w", err)
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum}},
		)
		exprs = append(exprs, applyPort(sPort, true)...)
		exprs = append(exprs, applyPort(dPort, false)...)
	}

	exprs = append(exprs, &expr.Counter{})
	return exprs, nil
}

func (r *family) hasRule(id firewall.RuleID) bool {
	_, ok := r.filters[id]
	return ok
}

func (r *family) hasDNATRule(id firewall.RuleID) bool {
	_, ok := r.rules[id+dnatSuffix]
	return ok
}

// DeleteFilterRule removes a previously installed filter rule. Source
// set references are recovered from the stored rule's expressions via
// findSets and dropped from the shared refcounter.
func (r *family) DeleteFilterRule(rule firewall.Rule) error {
	ruleID := rule.ID()
	pr, ok := r.filters[ruleID]
	if !ok {
		log.Debugf("filter rule %s not found", ruleID)
		return nil
	}

	// A freshly added rule carries no handle until it is read back from
	// the kernel, and Flush only refreshes the peer chains. Pull live
	// handles for this rule's chain before deciding it is stale so route
	// rules (which Flush never refreshes) can actually be deleted.
	if pr.nftRule.Handle == 0 {
		if err := r.refreshRuleHandles(pr.nftRule.Chain, false); err != nil {
			log.Warnf("refresh handles for chain %s: %v", pr.nftRule.Chain.Name, err)
		}
		if pr.mangleRule != nil {
			if err := r.refreshRuleHandles(r.chainPrerouting, true); err != nil {
				log.Warnf("refresh mangle handles: %v", err)
			}
		}
	}

	if pr.nftRule.Handle == 0 {
		log.Warnf("filter rule %s has no handle, removing stale entry", ruleID)
		r.dropNetworkMatch(pr.nftRule.Exprs)
		delete(r.filters, ruleID)
		return nil
	}

	if err := r.conn.DelRule(pr.nftRule); err != nil {
		log.Errorf("queue rule delete: %v", err)
	}
	if pr.mangleRule != nil {
		if err := r.conn.DelRule(pr.mangleRule); err != nil {
			log.Errorf("queue mangle rule delete: %v", err)
		}
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush delete %s: %w", ruleID, err)
	}

	r.dropNetworkMatch(pr.nftRule.Exprs)
	delete(r.filters, ruleID)
	return nil
}

func (r *family) decrementSetCounter(rule *nftables.Rule) error {
	if r.ipsetCounter == nil {
		return nil
	}
	sets := findSets(rule)

	var merr *multierror.Error
	for _, setName := range sets {
		if _, err := r.ipsetCounter.Decrement(setName); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("decrement set counter: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// dropNetworkMatch undoes whatever the source/destination match
// reserved. Safe to call when the spec is empty or holds only inline
// matchers.
func (r *family) dropNetworkMatch(exprs []expr.Any) {
	if r.ipsetCounter == nil {
		return
	}
	for _, e := range exprs {
		lookup, ok := e.(*expr.Lookup)
		if !ok {
			continue
		}
		if _, err := r.ipsetCounter.Decrement(lookup.SetName); err != nil {
			log.Errorf("rollback ipset decrement %s: %v", lookup.SetName, err)
		}
	}
}

func (r *family) applyNetwork(
	network firewall.Network,
	setPrefixes []netip.Prefix,
	isSource bool,
) ([]expr.Any, error) {
	if network.IsSet() {
		exprs, err := r.getIpSet(network.Set, setPrefixes, isSource)
		if err != nil {
			side := "destination"
			if isSource {
				side = "source"
			}
			return nil, fmt.Errorf("%s set: %w", side, err)
		}
		return exprs, nil
	}

	if network.IsPrefix() {
		return prefixMatchExprs(r.af, network.Prefix, isSource), nil
	}

	return nil, nil
}

// prefixMatchExprs is the family-aware match sequence for a CIDR
// prefix. /0 returns nil; a host prefix (full bit length for the
// family) skips the bitwise step since the mask is all-ones. Shared
// between family and aclManager so both treat single prefixes
// identically.
func prefixMatchExprs(af addrFamily, prefix netip.Prefix, isSource bool) []expr.Any {
	offset := af.dstAddrOffset
	if isSource {
		offset = af.srcAddrOffset
	}

	ones := prefix.Bits()
	if ones == 0 {
		return nil
	}

	payload := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          af.addrLen,
	}
	cmp := &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     prefix.Masked().Addr().AsSlice(),
	}

	if ones == af.totalBits {
		return []expr.Any{payload, cmp}
	}

	mask := net.CIDRMask(ones, af.totalBits)
	xor := make([]byte, af.addrLen)
	return []expr.Any{
		payload,
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            af.addrLen,
			Mask:           mask,
			Xor:            xor,
		},
		cmp,
	}
}

func applyPort(port *firewall.Port, isSource bool) []expr.Any {
	if port == nil {
		return nil
	}

	var exprs []expr.Any

	// src
	offset := uint32(2)
	if isSource {
		// dst
		offset = 0
	}

	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset,
		Len:          2,
	})

	if port.IsRange && len(port.Values) == 2 {
		exprs = append(exprs,
			&expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(port.Values[0]),
				ToData:   binaryutil.BigEndian.PutUint16(port.Values[1]),
			},
		)
	} else {
		for i, p := range port.Values {
			if i > 0 {
				exprs = append(exprs, &expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           []byte{0x00, 0x00, 0xff, 0xff},
					Xor:            []byte{0x00, 0x00, 0x00, 0x00},
				})
			}
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(p),
			})
		}
	}

	return exprs
}

func getCtNewExprs() []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
	}
}

// sourceNetwork classifies a source-prefix list into the firewall.Network
// shape the rest of the spec-builder consumes: empty for match-any, a
// single prefix inline, or an ipset for multiple sources.
func sourceNetwork(sources []netip.Prefix) firewall.Network {
	switch {
	case len(sources) == 0:
		return firewall.Network{}
	case len(sources) == 1 && sources[0].Bits() == 0:
		return firewall.Network{}
	case len(sources) == 1:
		return firewall.Network{Prefix: sources[0]}
	default:
		return firewall.Network{Set: firewall.NewPrefixSet(sources)}
	}
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

// findSets scans an nftables rule's expressions for expr.Lookup and
// returns the named sets in occurrence order. Used at delete time to
// drop ipsetCounter references; peer and route ACLs go through it.
func findSets(rule *nftables.Rule) []string {
	var sets []string
	for _, e := range rule.Exprs {
		if lookup, ok := e.(*expr.Lookup); ok {
			sets = append(sets, lookup.SetName)
		}
	}
	return sets
}
