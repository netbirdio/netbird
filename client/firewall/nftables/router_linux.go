package nftables

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

const (
	chainNameRoutingFw  = "netbird-rt-fwd"
	chainNameRoutingNat = "netbird-rt-postrouting"
	chainNameForward    = "FORWARD"

	userDataAcceptForwardRuleIif = "frwacceptiif"
	userDataAcceptForwardRuleOif = "frwacceptoif"
)

const refreshRulesMapError = "refresh rules map: %w"

var (
	errFilterTableNotFound = fmt.Errorf("nftables: 'filter' table not found")
)

type router struct {
	ctx         context.Context
	stop        context.CancelFunc
	conn        *nftables.Conn
	workTable   *nftables.Table
	filterTable *nftables.Table
	chains      map[string]*nftables.Chain
	// rules is useful to avoid duplicates and to get missing attributes that we don't have when adding new rules
	rules        map[string]*nftables.Rule
	ipsetCounter *refcounter.Counter[string, []netip.Prefix, *nftables.Set]

	wgIface          iFaceMapper
	legacyManagement bool
}

func newRouter(parentCtx context.Context, workTable *nftables.Table, wgIface iFaceMapper) (*router, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	r := &router{
		ctx:       ctx,
		stop:      cancel,
		conn:      &nftables.Conn{},
		workTable: workTable,
		chains:    make(map[string]*nftables.Chain),
		rules:     make(map[string]*nftables.Rule),
		wgIface:   wgIface,
	}

	r.ipsetCounter = refcounter.New(
		r.createIpSet,
		r.deleteIpSet,
	)

	var err error
	r.filterTable, err = r.loadFilterTable()
	if err != nil {
		if errors.Is(err, errFilterTableNotFound) {
			log.Warnf("table 'filter' not found for forward rules")
		} else {
			return nil, err
		}
	}

	err = r.cleanUpDefaultForwardRules()
	if err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	err = r.createContainers()
	if err != nil {
		log.Errorf("failed to create containers for route: %s", err)
	}
	return r, err
}

// Reset cleans existing nftables default forward rules from the system
func (r *router) Reset() error {
	// clear without deleting the ipsets, the nf table will be deleted by the caller
	r.ipsetCounter.Clear()

	return r.cleanUpDefaultForwardRules()
}

func (r *router) cleanUpDefaultForwardRules() error {
	if r.filterTable == nil {
		return nil
	}

	chains, err := r.conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("list chains: %v", err)
	}

	for _, chain := range chains {
		if chain.Table.Name != r.filterTable.Name || chain.Name != chainNameForward {
			continue
		}

		rules, err := r.conn.GetRules(r.filterTable, chain)
		if err != nil {
			return fmt.Errorf("get rules: %v", err)
		}

		for _, rule := range rules {
			if bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleIif)) ||
				bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleOif)) {
				if err := r.conn.DelRule(rule); err != nil {
					return fmt.Errorf("delete rule: %v", err)
				}
			}
		}
	}

	return r.conn.Flush()
}

func (r *router) loadFilterTable() (*nftables.Table, error) {
	tables, err := r.conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("nftables: unable to list tables: %v", err)
	}

	for _, table := range tables {
		if table.Name == "filter" {
			return table, nil
		}
	}

	return nil, errFilterTableNotFound
}

func (r *router) createContainers() error {
	r.chains[chainNameRoutingFw] = r.conn.AddChain(&nftables.Chain{
		Name:  chainNameRoutingFw,
		Table: r.workTable,
	})

	insertReturnTrafficRule(r.conn, r.workTable, r.chains[chainNameRoutingFw])

	prio := *nftables.ChainPriorityNATSource - 1

	r.chains[chainNameRoutingNat] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameRoutingNat,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: &prio,
		Type:     nftables.ChainTypeNAT,
	})

	r.acceptForwardRules()

	if err := r.refreshRulesMap(); err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: unable to initialize table: %v", err)
	}

	return nil
}

// AddRouteFiltering appends a nftables rule to the routing chain
func (r *router) AddRouteFiltering(
	sources []netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {

	ruleKey := id.GenerateRouteRuleKey(sources, destination, proto, sPort, dPort, action)
	if _, ok := r.rules[string(ruleKey)]; ok {
		return ruleKey, nil
	}

	chain := r.chains[chainNameRoutingFw]
	var exprs []expr.Any

	switch {
	case len(sources) == 1 && sources[0].Bits() == 0:
		// If it's 0.0.0.0/0, we don't need to add any source matching
	case len(sources) == 1:
		// If there's only one source, we can use it directly
		exprs = append(exprs, generateCIDRMatcherExpressions(true, sources[0])...)
	default:
		// If there are multiple sources, create or get an ipset
		var err error
		exprs, err = r.getIpSetExprs(sources, exprs)
		if err != nil {
			return nil, fmt.Errorf("get ipset expressions: %w", err)
		}
	}

	// Handle destination
	exprs = append(exprs, generateCIDRMatcherExpressions(false, destination)...)

	// Handle protocol
	if proto != firewall.ProtocolALL {
		protoNum, err := protoToInt(proto)
		if err != nil {
			return nil, fmt.Errorf("convert protocol to number: %w", err)
		}
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protoNum},
		})

		exprs = append(exprs, applyPort(sPort, true)...)
		exprs = append(exprs, applyPort(dPort, false)...)
	}

	exprs = append(exprs, &expr.Counter{})

	var verdict expr.VerdictKind
	if action == firewall.ActionAccept {
		verdict = expr.VerdictAccept
	} else {
		verdict = expr.VerdictDrop
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdict})

	rule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(ruleKey),
	}

	rule = r.conn.AddRule(rule)

	log.Tracef("Adding route rule %s", spew.Sdump(rule))
	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf(flushError, err)
	}

	r.rules[string(ruleKey)] = rule

	log.Debugf("nftables: added route rule: sources=%v, destination=%v, proto=%v, sPort=%v, dPort=%v, action=%v", sources, destination, proto, sPort, dPort, action)

	return ruleKey, nil
}

func (r *router) getIpSetExprs(sources []netip.Prefix, exprs []expr.Any) ([]expr.Any, error) {
	setName := firewall.GenerateSetName(sources)
	ref, err := r.ipsetCounter.Increment(setName, sources)
	if err != nil {
		return nil, fmt.Errorf("create or get ipset for sources: %w", err)
	}

	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        ref.Out.Name,
			SetID:          ref.Out.ID,
		},
	)
	return exprs, nil
}

func (r *router) DeleteRouteRule(rule firewall.Rule) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	ruleKey := rule.GetRuleID()
	nftRule, exists := r.rules[ruleKey]
	if !exists {
		log.Debugf("route rule %s not found", ruleKey)
		return nil
	}

	if nftRule.Handle == 0 {
		return fmt.Errorf("route rule %s has no handle", ruleKey)
	}

	setName := r.findSetNameInRule(nftRule)

	if err := r.deleteNftRule(nftRule, ruleKey); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	if setName != "" {
		if _, err := r.ipsetCounter.Decrement(setName); err != nil {
			return fmt.Errorf("decrement ipset reference: %w", err)
		}
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	return nil
}

func (r *router) createIpSet(setName string, sources []netip.Prefix) (*nftables.Set, error) {
	// overlapping prefixes will result in an error, so we need to merge them
	sources = firewall.MergeIPRanges(sources)

	set := &nftables.Set{
		Name:  setName,
		Table: r.workTable,
		// required for prefixes
		Interval: true,
		KeyType:  nftables.TypeIPAddr,
	}

	var elements []nftables.SetElement
	for _, prefix := range sources {
		// TODO: Implement IPv6 support
		if prefix.Addr().Is6() {
			log.Printf("Skipping IPv6 prefix %s: IPv6 support not yet implemented", prefix)
			continue
		}

		// nftables needs half-open intervals [firstIP, lastIP) for prefixes
		// e.g. 10.0.0.0/24 becomes [10.0.0.0, 10.0.1.0), 10.1.1.1/32 becomes [10.1.1.1, 10.1.1.2) etc
		firstIP := prefix.Addr()
		lastIP := calculateLastIP(prefix).Next()

		elements = append(elements,
			// the nft tool also adds a line like this, see https://github.com/google/nftables/issues/247
			// nftables.SetElement{Key: []byte{0, 0, 0, 0}, IntervalEnd: true},
			nftables.SetElement{Key: firstIP.AsSlice()},
			nftables.SetElement{Key: lastIP.AsSlice(), IntervalEnd: true},
		)
	}

	if err := r.conn.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("error adding elements to set %s: %w", setName, err)
	}

	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush error: %w", err)
	}

	log.Printf("Created new ipset: %s with %d elements", setName, len(elements)/2)

	return set, nil
}

// calculateLastIP determines the last IP in a given prefix.
func calculateLastIP(prefix netip.Prefix) netip.Addr {
	hostMask := ^uint32(0) >> prefix.Masked().Bits()
	lastIP := uint32FromNetipAddr(prefix.Addr()) | hostMask

	return netip.AddrFrom4(uint32ToBytes(lastIP))
}

// Utility function to convert netip.Addr to uint32.
func uint32FromNetipAddr(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Utility function to convert uint32 to a netip-compatible byte slice.
func uint32ToBytes(ip uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return b
}

func (r *router) deleteIpSet(setName string, set *nftables.Set) error {
	r.conn.DelSet(set)
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	log.Debugf("Deleted unused ipset %s", setName)
	return nil
}

func (r *router) findSetNameInRule(rule *nftables.Rule) string {
	for _, e := range rule.Exprs {
		if lookup, ok := e.(*expr.Lookup); ok {
			return lookup.SetName
		}
	}
	return ""
}

func (r *router) deleteNftRule(rule *nftables.Rule, ruleKey string) error {
	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("delete rule %s: %w", ruleKey, err)
	}
	delete(r.rules, ruleKey)

	log.Debugf("removed route rule %s", ruleKey)

	return nil
}

// AddNatRule appends a nftables rule pair to the nat chain
func (r *router) AddNatRule(pair firewall.RouterPair) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

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

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: insert rules for %s: %v", pair.Destination, err)
	}

	return nil
}

// addNatRule inserts a nftables rule to the conn client flush queue
func (r *router) addNatRule(pair firewall.RouterPair) error {
	sourceExp := generateCIDRMatcherExpressions(true, pair.Source)
	destExp := generateCIDRMatcherExpressions(false, pair.Destination)

	dir := expr.MetaKeyIIFNAME
	if pair.Inverse {
		dir = expr.MetaKeyOIFNAME
	}

	intf := ifname(r.wgIface.Name())
	exprs := []expr.Any{
		&expr.Meta{
			Key:      dir,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     intf,
		},
	}

	exprs = append(exprs, sourceExp...)
	exprs = append(exprs, destExp...)
	exprs = append(exprs,
		&expr.Counter{}, &expr.Masq{},
	)

	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if _, exists := r.rules[ruleKey]; exists {
		if err := r.removeNatRule(pair); err != nil {
			return fmt.Errorf("remove routing rule: %w", err)
		}
	}

	r.rules[ruleKey] = r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingNat],
		Exprs:    exprs,
		UserData: []byte(ruleKey),
	})
	return nil
}

// addLegacyRouteRule adds a legacy routing rule for mgmt servers pre route acls
func (r *router) addLegacyRouteRule(pair firewall.RouterPair) error {
	sourceExp := generateCIDRMatcherExpressions(true, pair.Source)
	destExp := generateCIDRMatcherExpressions(false, pair.Destination)

	exprs := []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	expression := append(sourceExp, append(destExp, exprs...)...) // nolint:gocritic

	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	if _, exists := r.rules[ruleKey]; exists {
		if err := r.removeLegacyRouteRule(pair); err != nil {
			return fmt.Errorf("remove legacy routing rule: %w", err)
		}
	}

	r.rules[ruleKey] = r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingFw],
		Exprs:    expression,
		UserData: []byte(ruleKey),
	})
	return nil
}

// removeLegacyRouteRule removes a legacy routing rule for mgmt servers pre route acls
func (r *router) removeLegacyRouteRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		if err := r.conn.DelRule(rule); err != nil {
			return fmt.Errorf("remove legacy forwarding rule %s -> %s: %v", pair.Source, pair.Destination, err)
		}

		log.Debugf("nftables: removed legacy forwarding rule %s -> %s", pair.Source, pair.Destination)

		delete(r.rules, ruleKey)
	} else {
		log.Debugf("nftables: legacy forwarding rule %s not found", ruleKey)
	}

	return nil
}

// GetLegacyManagement returns the route manager's legacy management mode
func (r *router) GetLegacyManagement() bool {
	return r.legacyManagement
}

// SetLegacyManagement sets the route manager to use legacy management mode
func (r *router) SetLegacyManagement(isLegacy bool) {
	r.legacyManagement = isLegacy
}

// RemoveAllLegacyRouteRules removes all legacy routing rules for mgmt servers pre route acls
func (r *router) RemoveAllLegacyRouteRules() error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	var merr *multierror.Error
	for k, rule := range r.rules {
		if !strings.HasPrefix(k, firewall.ForwardingFormatPrefix) {
			continue
		}
		if err := r.conn.DelRule(rule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove legacy forwarding rule: %v", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// acceptForwardRules adds iif/oif rules in the filter table/forward chain to make sure
// that our traffic is not dropped by existing rules there.
// The existing FORWARD rules/policies decide outbound traffic towards our interface.
// In case the FORWARD policy is set to "drop", we add an established/related rule to allow return traffic for the inbound rule.
func (r *router) acceptForwardRules() {
	if r.filterTable == nil {
		log.Debugf("table 'filter' not found for forward rules, skipping accept rules")
		return
	}

	intf := ifname(r.wgIface.Name())

	// Rule for incoming interface (iif) with counter
	iifRule := &nftables.Rule{
		Table: r.filterTable,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    r.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     intf,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		UserData: []byte(userDataAcceptForwardRuleIif),
	}
	r.conn.InsertRule(iifRule)

	// Rule for outgoing interface (oif) with counter
	oifRule := &nftables.Rule{
		Table: r.filterTable,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    r.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     intf,
			},
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 2,
			},
			&expr.Bitwise{
				SourceRegister: 2,
				DestRegister:   2,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 2,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		UserData: []byte(userDataAcceptForwardRuleOif),
	}

	r.conn.InsertRule(oifRule)
}

// RemoveNatRule removes a nftables rule pair from nat chains
func (r *router) RemoveNatRule(pair firewall.RouterPair) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	if err := r.removeNatRule(pair); err != nil {
		return fmt.Errorf("remove nat rule: %w", err)
	}

	if err := r.removeNatRule(firewall.GetInversePair(pair)); err != nil {
		return fmt.Errorf("remove inverse nat rule: %w", err)
	}

	if err := r.removeLegacyRouteRule(pair); err != nil {
		return fmt.Errorf("remove legacy routing rule: %w", err)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: received error while applying rule removal for %s: %v", pair.Destination, err)
	}

	log.Debugf("nftables: removed nat rules for %s", pair.Destination)
	return nil
}

// removeNatRule adds a nftables rule to the removal queue and deletes it from the rules map
func (r *router) removeNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.NatFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		err := r.conn.DelRule(rule)
		if err != nil {
			return fmt.Errorf("remove nat rule %s -> %s: %v", pair.Source, pair.Destination, err)
		}

		log.Debugf("nftables: removed nat rule %s -> %s", pair.Source, pair.Destination)

		delete(r.rules, ruleKey)
	} else {
		log.Debugf("nftables: nat rule %s not found", ruleKey)
	}

	return nil
}

// refreshRulesMap refreshes the rule map with the latest rules. this is useful to avoid
// duplicates and to get missing attributes that we don't have when adding new rules
func (r *router) refreshRulesMap() error {
	for _, chain := range r.chains {
		rules, err := r.conn.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("nftables: unable to list rules: %v", err)
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				r.rules[string(rule.UserData)] = rule
			}
		}
	}
	return nil
}

// generateCIDRMatcherExpressions generates nftables expressions that matches a CIDR
func generateCIDRMatcherExpressions(source bool, prefix netip.Prefix) []expr.Any {
	var offset uint32
	if source {
		offset = 12 // src offset
	} else {
		offset = 16 // dst offset
	}

	ones := prefix.Bits()
	// 0.0.0.0/0 doesn't need extra expressions
	if ones == 0 {
		return nil
	}

	mask := net.CIDRMask(ones, 32)

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		},
		// netmask
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0},
		},
		// net address
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     prefix.Masked().Addr().AsSlice(),
		},
	}
}

func applyPort(port *firewall.Port, isSource bool) []expr.Any {
	if port == nil {
		return nil
	}

	var exprs []expr.Any

	offset := uint32(2) // Default offset for destination port
	if isSource {
		offset = 0 // Offset for source port
	}

	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset,
		Len:          2,
	})

	if port.IsRange && len(port.Values) == 2 {
		// Handle port range
		exprs = append(exprs,
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(port.Values[0])),
			},
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(port.Values[1])),
			},
		)
	} else {
		// Handle single port or multiple ports
		for i, p := range port.Values {
			if i > 0 {
				// Add a bitwise OR operation between port checks
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
				Data:     binaryutil.BigEndian.PutUint16(uint16(p)),
			})
		}
	}

	return exprs
}
