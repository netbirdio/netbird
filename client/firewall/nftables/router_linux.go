package nftables

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	nbnet "github.com/netbirdio/netbird/util/net"
)

const (
	tableNat               = "nat"
	chainNameNatPrerouting = "PREROUTING"
	chainNameRoutingFw     = "netbird-rt-fwd"
	chainNameRoutingNat    = "netbird-rt-postrouting"
	chainNameRoutingRdr    = "netbird-rt-redirect"
	chainNameForward       = "FORWARD"

	userDataAcceptForwardRuleIif = "frwacceptiif"
	userDataAcceptForwardRuleOif = "frwacceptoif"

	dnatSuffix = "_dnat"
	snatSuffix = "_snat"
)

const refreshRulesMapError = "refresh rules map: %w"

var (
	errFilterTableNotFound = fmt.Errorf("nftables: 'filter' table not found")
)

type router struct {
	conn        *nftables.Conn
	workTable   *nftables.Table
	filterTable *nftables.Table
	chains      map[string]*nftables.Chain
	// rules is useful to avoid duplicates and to get missing attributes that we don't have when adding new rules
	rules        map[string]*nftables.Rule
	ipsetCounter *refcounter.Counter[string, []netip.Prefix, *nftables.Set]

	wgIface          iFaceMapper
	ipFwdState       *ipfwdstate.IPForwardingState
	legacyManagement bool
}

func newRouter(workTable *nftables.Table, wgIface iFaceMapper) (*router, error) {
	r := &router{
		conn:       &nftables.Conn{},
		workTable:  workTable,
		chains:     make(map[string]*nftables.Chain),
		rules:      make(map[string]*nftables.Rule),
		wgIface:    wgIface,
		ipFwdState: ipfwdstate.NewIPForwardingState(),
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
			return nil, fmt.Errorf("load filter table: %w", err)
		}
	}

	return r, nil
}

func (r *router) init(workTable *nftables.Table) error {
	r.workTable = workTable

	if err := r.removeAcceptForwardRules(); err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	return nil
}

// Reset cleans existing nftables default forward rules from the system
func (r *router) Reset() error {
	// clear without deleting the ipsets, the nf table will be deleted by the caller
	r.ipsetCounter.Clear()

	var merr *multierror.Error

	if err := r.removeAcceptForwardRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove accept forward rules: %w", err))
	}

	if err := r.removeNatPreroutingRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove filter prerouting rules: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) removeNatPreroutingRules() error {
	table := &nftables.Table{
		Name:   tableNat,
		Family: nftables.TableFamilyIPv4,
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
		if len(rule.UserData) == 0 || !strings.HasSuffix(string(rule.UserData), dnatSuffix) {
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

	r.chains[chainNameRoutingRdr] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameRoutingRdr,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})

	// Chain is created by acl manager
	// TODO: move creation to a common place
	r.chains[chainNamePrerouting] = &nftables.Chain{
		Name:     chainNamePrerouting,
		Table:    r.workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	}

	// Add the single NAT rule that matches on mark
	if err := r.addPostroutingRules(); err != nil {
		return fmt.Errorf("add single nat rule: %v", err)
	}

	if err := r.acceptForwardRules(); err != nil {
		log.Errorf("failed to add accept rules for the forward chain: %s", err)
	}

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
	id []byte,
	sources []netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {

	ruleKey := nbid.GenerateRouteRuleKey(sources, destination, proto, sPort, dPort, action)
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

	// Insert DROP rules at the beginning, append ACCEPT rules at the end
	if action == firewall.ActionDrop {
		// TODO: Insert after the established rule
		rule = r.conn.InsertRule(rule)
	} else {
		rule = r.conn.AddRule(rule)
	}

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

	ruleKey := rule.ID()
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
	if err := r.ipFwdState.RequestForwarding(); err != nil {
		return err
	}

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

	op := expr.CmpOpEq
	if pair.Inverse {
		op = expr.CmpOpNeq
	}

	exprs := []expr.Any{
		// We only care about NEW connections to mark them and later identify them in the postrouting chain for masquerading.
		// Masquerading will take care of the conntrack state, which means we won't need to mark established connections.
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

		// interface matching
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

	ruleKey := firewall.GenKey(firewall.PreroutingFormat, pair)

	if _, exists := r.rules[ruleKey]; exists {
		if err := r.removeNatRule(pair); err != nil {
			return fmt.Errorf("remove prerouting rule: %w", err)
		}
	}

	r.rules[ruleKey] = r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNamePrerouting],
		Exprs:    exprs,
		UserData: []byte(ruleKey),
	})

	return nil
}

// addPostroutingRules adds the masquerade rules
func (r *router) addPostroutingRules() error {
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
		} else {
			delete(r.rules, k)
		}

	}
	return nberrors.FormatErrorOrNil(merr)
}

// acceptForwardRules adds iif/oif rules in the filter table/forward chain to make sure
// that our traffic is not dropped by existing rules there.
// The existing FORWARD rules/policies decide outbound traffic towards our interface.
// In case the FORWARD policy is set to "drop", we add an established/related rule to allow return traffic for the inbound rule.
func (r *router) acceptForwardRules() error {
	if r.filterTable == nil {
		log.Debugf("table 'filter' not found for forward rules, skipping accept rules")
		return nil
	}

	fw := "iptables"

	defer func() {
		log.Debugf("Used %s to add accept forward rules", fw)
	}()

	// Try iptables first and fallback to nftables if iptables is not available
	ipt, err := iptables.New()
	if err != nil {
		// filter table exists but iptables is not
		log.Warnf("Will use nftables to manipulate the filter table because iptables is not available: %v", err)

		fw = "nftables"
		return r.acceptForwardRulesNftables()
	}

	return r.acceptForwardRulesIptables(ipt)
}

func (r *router) acceptForwardRulesIptables(ipt *iptables.IPTables) error {
	var merr *multierror.Error
	for _, rule := range r.getAcceptForwardRules() {
		if err := ipt.Insert("filter", chainNameForward, 1, rule...); err != nil {
			merr = multierror.Append(err, fmt.Errorf("add iptables rule: %v", err))
		} else {
			log.Debugf("added iptables rule: %v", rule)
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) getAcceptForwardRules() [][]string {
	intf := r.wgIface.Name()
	return [][]string{
		{"-i", intf, "-j", "ACCEPT"},
		{"-o", intf, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
}

func (r *router) acceptForwardRulesNftables() error {
	intf := ifname(r.wgIface.Name())

	// Rule for incoming interface (iif) with counter
	iifRule := &nftables.Rule{
		Table: r.filterTable,
		Chain: &nftables.Chain{
			Name:     chainNameForward,
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

	oifExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     intf,
		},
	}

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
		Exprs:    append(oifExprs, getEstablishedExprs(2)...),
		UserData: []byte(userDataAcceptForwardRuleOif),
	}

	r.conn.InsertRule(oifRule)

	return nil
}

func (r *router) removeAcceptForwardRules() error {
	if r.filterTable == nil {
		return nil
	}

	// Try iptables first and fallback to nftables if iptables is not available
	ipt, err := iptables.New()
	if err != nil {
		log.Warnf("Will use nftables to manipulate the filter table because iptables is not available: %v", err)
		return r.removeAcceptForwardRulesNftables()
	}

	return r.removeAcceptForwardRulesIptables(ipt)
}

func (r *router) removeAcceptForwardRulesNftables() error {
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

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	return nil
}

func (r *router) removeAcceptForwardRulesIptables(ipt *iptables.IPTables) error {
	var merr *multierror.Error
	for _, rule := range r.getAcceptForwardRules() {
		if err := ipt.DeleteIfExists("filter", chainNameForward, rule...); err != nil {
			merr = multierror.Append(err, fmt.Errorf("remove iptables rule: %v", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// RemoveNatRule removes the prerouting mark rule
func (r *router) RemoveNatRule(pair firewall.RouterPair) error {
	if err := r.ipFwdState.ReleaseForwarding(); err != nil {
		log.Errorf("%v", err)
	}

	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	if err := r.removeNatRule(pair); err != nil {
		return fmt.Errorf("remove prerouting rule: %w", err)
	}

	if err := r.removeNatRule(firewall.GetInversePair(pair)); err != nil {
		return fmt.Errorf("remove inverse prerouting rule: %w", err)
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

func (r *router) removeNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.PreroutingFormat, pair)

	if rule, exists := r.rules[ruleKey]; exists {
		err := r.conn.DelRule(rule)
		if err != nil {
			return fmt.Errorf("remove prerouting rule %s -> %s: %v", pair.Source, pair.Destination, err)
		}

		log.Debugf("nftables: removed prerouting rule %s -> %s", pair.Source, pair.Destination)

		delete(r.rules, ruleKey)
	} else {
		log.Debugf("nftables: prerouting rule %s not found", ruleKey)
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

func (r *router) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	if err := r.ipFwdState.RequestForwarding(); err != nil {
		return nil, err
	}

	ruleKey := rule.ID()
	if _, exists := r.rules[ruleKey+dnatSuffix]; exists {
		return rule, nil
	}

	protoNum, err := protoToInt(rule.Protocol)
	if err != nil {
		return nil, fmt.Errorf("convert protocol to number: %w", err)
	}

	if err := r.addDnatRedirect(rule, protoNum, ruleKey); err != nil {
		return nil, err
	}

	r.addDnatMasq(rule, protoNum, ruleKey)

	// Unlike iptables, there's no point in adding "out" rules in the forward chain here as our policy is ACCEPT.
	// To overcome DROP policies in other chains, we'd have to add rules to the chains there.
	// We also cannot just add "oif <iface> accept" there and filter in our own table as we don't know what is supposed to be allowed.
	// TODO: find chains with drop policies and add rules there

	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush rules: %w", err)
	}

	return &rule, nil
}

func (r *router) addDnatRedirect(rule firewall.ForwardRule, protoNum uint8, ruleKey string) error {
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
	dnatExprs = append(dnatExprs, applyPort(&rule.DestinationPort, false)...)

	// shifted translated port is not supported in nftables, so we hand this over to xtables
	if rule.TranslatedPort.IsRange && len(rule.TranslatedPort.Values) == 2 {
		if rule.TranslatedPort.Values[0] != rule.DestinationPort.Values[0] ||
			rule.TranslatedPort.Values[1] != rule.DestinationPort.Values[1] {
			return r.addXTablesRedirect(dnatExprs, ruleKey, rule)
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
			Family:      uint32(nftables.TableFamilyIPv4),
			RegAddrMin:  1,
			RegProtoMin: regProtoMin,
			RegProtoMax: regProtoMax,
		},
	)

	dnatRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingRdr],
		Exprs:    dnatExprs,
		UserData: []byte(ruleKey + dnatSuffix),
	}
	r.conn.AddRule(dnatRule)
	r.rules[ruleKey+dnatSuffix] = dnatRule

	return nil
}

func (r *router) handleTranslatedPort(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
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

func (r *router) handlePortRange(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
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

func (r *router) handleAddressOnly(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
	exprs := []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
	}
	return exprs, 0, 0, nil
}

func (r *router) handleSinglePort(rule firewall.ForwardRule) ([]expr.Any, uint32, uint32, error) {
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

func (r *router) addXTablesRedirect(dnatExprs []expr.Any, ruleKey string, rule firewall.ForwardRule) error {
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

	dnatRule := &nftables.Rule{
		Table: &nftables.Table{
			Name:   tableNat,
			Family: nftables.TableFamilyIPv4,
		},
		Chain: &nftables.Chain{
			Name:     chainNameNatPrerouting,
			Table:    r.filterTable,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityNATDest,
		},
		Exprs:    dnatExprs,
		UserData: []byte(ruleKey + dnatSuffix),
	}
	r.conn.AddRule(dnatRule)
	r.rules[ruleKey+dnatSuffix] = dnatRule

	return nil
}

func (r *router) addDnatMasq(rule firewall.ForwardRule, protoNum uint8, ruleKey string) {
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
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     rule.TranslatedAddress.AsSlice(),
		},
	}

	masqExprs = append(masqExprs, applyPort(&rule.TranslatedPort, false)...)
	masqExprs = append(masqExprs, &expr.Masq{})

	masqRule := &nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingNat],
		Exprs:    masqExprs,
		UserData: []byte(ruleKey + snatSuffix),
	}
	r.conn.AddRule(masqRule)
	r.rules[ruleKey+snatSuffix] = masqRule
}

func (r *router) DeleteDNATRule(rule firewall.Rule) error {
	if err := r.ipFwdState.ReleaseForwarding(); err != nil {
		log.Errorf("%v", err)
	}

	ruleKey := rule.ID()

	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	var merr *multierror.Error
	if dnatRule, exists := r.rules[ruleKey+dnatSuffix]; exists {
		if err := r.conn.DelRule(dnatRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete dnat rule: %w", err))
		}
	}

	if masqRule, exists := r.rules[ruleKey+snatSuffix]; exists {
		if err := r.conn.DelRule(masqRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete snat rule: %w", err))
		}
	}

	if err := r.conn.Flush(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf(flushError, err))
	}

	if merr == nil {
		delete(r.rules, ruleKey+dnatSuffix)
		delete(r.rules, ruleKey+snatSuffix)
	}

	return nberrors.FormatErrorOrNil(merr)
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
			&expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(port.Values[0]),
				ToData:   binaryutil.BigEndian.PutUint16(port.Values[1]),
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
				Data:     binaryutil.BigEndian.PutUint16(p),
			})
		}
	}

	return exprs
}
