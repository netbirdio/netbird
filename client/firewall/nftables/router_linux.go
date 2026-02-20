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
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	tableNat      = "nat"
	tableMangle   = "mangle"
	tableRaw      = "raw"
	tableSecurity = "security"

	chainNameNatPrerouting = "PREROUTING"
	chainNameRoutingFw     = "netbird-rt-fwd"
	chainNameRoutingNat    = "netbird-rt-postrouting"
	chainNameRoutingRdr    = "netbird-rt-redirect"
	chainNameForward       = "FORWARD"
	chainNameMangleForward = "netbird-mangle-forward"

	userDataAcceptForwardRuleIif = "frwacceptiif"
	userDataAcceptForwardRuleOif = "frwacceptoif"
	userDataAcceptInputRule      = "inputaccept"

	dnatSuffix = "_dnat"
	snatSuffix = "_snat"

	// ipTCPHeaderMinSize represents minimum IP (20) + TCP (20) header size for MSS calculation
	ipTCPHeaderMinSize = 40

	// maxPrefixesSet 1638 prefixes start to fail, taking some margin
	maxPrefixesSet       = 1500
	refreshRulesMapError = "refresh rules map: %w"
)

var (
	errFilterTableNotFound = fmt.Errorf("'filter' table not found")
)

type setInput struct {
	set      firewall.Set
	prefixes []netip.Prefix
}

type router struct {
	conn        *nftables.Conn
	workTable   *nftables.Table
	filterTable *nftables.Table
	chains      map[string]*nftables.Chain
	// rules is useful to avoid duplicates and to get missing attributes that we don't have when adding new rules
	rules        map[string]*nftables.Rule
	ipsetCounter *refcounter.Counter[string, setInput, *nftables.Set]

	wgIface          iFaceMapper
	ipFwdState       *ipfwdstate.IPForwardingState
	legacyManagement bool
	mtu              uint16
}

func newRouter(workTable *nftables.Table, wgIface iFaceMapper, mtu uint16) (*router, error) {
	r := &router{
		conn:       &nftables.Conn{},
		workTable:  workTable,
		chains:     make(map[string]*nftables.Chain),
		rules:      make(map[string]*nftables.Rule),
		wgIface:    wgIface,
		ipFwdState: ipfwdstate.NewIPForwardingState(),
		mtu:        mtu,
	}

	r.ipsetCounter = refcounter.New(
		r.createIpSet,
		r.deleteIpSet,
	)

	var err error
	r.filterTable, err = r.loadFilterTable()
	if err != nil {
		log.Debugf("ip filter table not found: %v", err)
	}

	return r, nil
}

func (r *router) init(workTable *nftables.Table) error {
	r.workTable = workTable

	if err := r.removeAcceptFilterRules(); err != nil {
		log.Errorf("failed to clean up rules from filter table: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	if err := r.setupDataPlaneMark(); err != nil {
		log.Errorf("failed to set up data plane mark: %v", err)
	}

	return nil
}

// Reset cleans existing nftables filter table rules from the system
func (r *router) Reset() error {
	// clear without deleting the ipsets, the nf table will be deleted by the caller
	r.ipsetCounter.Clear()

	var merr *multierror.Error

	if err := r.removeAcceptFilterRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove accept filter rules: %w", err))
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
		return nil, fmt.Errorf("list tables: %w", err)
	}

	for _, table := range tables {
		if table.Name == "filter" {
			return table, nil
		}
	}

	return nil, errFilterTableNotFound
}

func hookName(hook *nftables.ChainHook) string {
	if hook == nil {
		return "unknown"
	}
	switch *hook {
	case *nftables.ChainHookForward:
		return chainNameForward
	case *nftables.ChainHookInput:
		return chainNameInput
	default:
		return fmt.Sprintf("hook(%d)", *hook)
	}
}

func familyName(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	default:
		return fmt.Sprintf("family(%d)", family)
	}
}

func (r *router) createContainers() error {
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

	if err := r.acceptForwardRules(); err != nil {
		log.Errorf("failed to add accept rules for the forward chain: %s", err)
	}

	if err := r.refreshRulesMap(); err != nil {
		log.Errorf("failed to refresh rules: %s", err)
	}

	return nil
}

// setupDataPlaneMark configures the fwmark for the data plane
func (r *router) setupDataPlaneMark() error {
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

// AddRouteFiltering appends a nftables rule to the routing chain
func (r *router) AddRouteFiltering(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
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

	var source firewall.Network
	switch {
	case len(sources) == 1 && sources[0].Bits() == 0:
		// If it's 0.0.0.0/0, we don't need to add any source matching
	case len(sources) == 1:
		// If there's only one source, we can use it directly
		source.Prefix = sources[0]
	default:
		// If there are multiple sources, use a set
		source.Set = firewall.NewPrefixSet(sources)
	}

	sourceExp, err := r.applyNetwork(source, sources, true)
	if err != nil {
		return nil, fmt.Errorf("apply source: %w", err)
	}
	exprs = append(exprs, sourceExp...)

	destExp, err := r.applyNetwork(destination, nil, false)
	if err != nil {
		return nil, fmt.Errorf("apply destination: %w", err)
	}
	exprs = append(exprs, destExp...)

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

	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf(flushError, err)
	}

	r.rules[string(ruleKey)] = rule

	log.Debugf("added route rule: sources=%v, destination=%v, proto=%v, sPort=%v, dPort=%v, action=%v", sources, destination, proto, sPort, dPort, action)

	return ruleKey, nil
}

func (r *router) getIpSet(set firewall.Set, prefixes []netip.Prefix, isSource bool) ([]expr.Any, error) {
	ref, err := r.ipsetCounter.Increment(set.HashedName(), setInput{
		set:      set,
		prefixes: prefixes,
	})
	if err != nil {
		return nil, fmt.Errorf("create or get ipset: %w", err)
	}

	return getIpSetExprs(ref, isSource)
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
		log.Warnf("route rule %s has no handle, removing stale entry", ruleKey)
		if err := r.decrementSetCounter(nftRule); err != nil {
			log.Warnf("decrement set counter for stale rule %s: %v", ruleKey, err)
		}
		delete(r.rules, ruleKey)
		return nil
	}

	if err := r.deleteNftRule(nftRule, ruleKey); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	if err := r.decrementSetCounter(nftRule); err != nil {
		return fmt.Errorf("decrement set counter: %w", err)
	}

	return nil
}

func (r *router) createIpSet(setName string, input setInput) (*nftables.Set, error) {
	// overlapping prefixes will result in an error, so we need to merge them
	prefixes := firewall.MergeIPRanges(input.prefixes)

	nfset := &nftables.Set{
		Name:    setName,
		Comment: input.set.Comment(),
		Table:   r.workTable,
		// required for prefixes
		Interval: true,
		KeyType:  nftables.TypeIPAddr,
	}

	elements := convertPrefixesToSet(prefixes)
	nElements := len(elements)

	maxElements := maxPrefixesSet * 2
	initialElements := elements[:min(maxElements, nElements)]

	if err := r.conn.AddSet(nfset, initialElements); err != nil {
		return nil, fmt.Errorf("error adding set %s: %w", setName, err)
	}
	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush error: %w", err)
	}
	log.Debugf("Created new ipset: %s with %d initial prefixes (total prefixes %d)", setName, len(initialElements)/2, len(prefixes))

	var subEnd int
	for subStart := maxElements; subStart < nElements; subStart += maxElements {
		subEnd = min(subStart+maxElements, nElements)
		subElement := elements[subStart:subEnd]
		nSubPrefixes := len(subElement) / 2
		log.Tracef("Adding new prefixes (%d) in ipset: %s", nSubPrefixes, setName)
		if err := r.conn.SetAddElements(nfset, subElement); err != nil {
			return nil, fmt.Errorf("error adding prefixes (%d) to set %s: %w", nSubPrefixes, setName, err)
		}
		if err := r.conn.Flush(); err != nil {
			return nil, fmt.Errorf("flush error: %w", err)
		}
		log.Debugf("Added new prefixes (%d) in ipset: %s", nSubPrefixes, setName)
	}

	log.Infof("Created new ipset: %s with %d prefixes", setName, len(prefixes))
	return nfset, nil
}

func convertPrefixesToSet(prefixes []netip.Prefix) []nftables.SetElement {
	var elements []nftables.SetElement
	for _, prefix := range prefixes {
		// TODO: Implement IPv6 support
		if prefix.Addr().Is6() {
			log.Tracef("skipping IPv6 prefix %s: IPv6 support not yet implemented", prefix)
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
	return elements
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

func (r *router) deleteIpSet(setName string, nfset *nftables.Set) error {
	r.conn.DelSet(nfset)
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	log.Debugf("Deleted unused ipset %s", setName)
	return nil
}

func (r *router) decrementSetCounter(rule *nftables.Rule) error {
	sets := r.findSets(rule)

	var merr *multierror.Error
	for _, setName := range sets {
		if _, err := r.ipsetCounter.Decrement(setName); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("decrement set counter: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) findSets(rule *nftables.Rule) []string {
	var sets []string
	for _, e := range rule.Exprs {
		if lookup, ok := e.(*expr.Lookup); ok {
			sets = append(sets, lookup.SetName)
		}
	}
	return sets
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
		r.rollbackRules(pair)
		return fmt.Errorf("insert rules for %s: %w", pair.Destination, err)
	}

	return nil
}

// rollbackRules cleans up unflushed rules and their set counters after a flush failure.
func (r *router) rollbackRules(pair firewall.RouterPair) {
	keys := []string{
		firewall.GenKey(firewall.ForwardingFormat, pair),
		firewall.GenKey(firewall.PreroutingFormat, pair),
		firewall.GenKey(firewall.PreroutingFormat, firewall.GetInversePair(pair)),
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
func (r *router) addNatRule(pair firewall.RouterPair) error {
	sourceExp, err := r.applyNetwork(pair.Source, nil, true)
	if err != nil {
		return fmt.Errorf("apply source: %w", err)
	}

	destExp, err := r.applyNetwork(pair.Destination, nil, false)
	if err != nil {
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

	ruleKey := firewall.GenKey(firewall.PreroutingFormat, pair)

	if _, exists := r.rules[ruleKey]; exists {
		if err := r.removeNatRule(pair); err != nil {
			return fmt.Errorf("remove prerouting rule: %w", err)
		}
	}

	// Ensure nat rules come first, so the mark can be overwritten.
	// Currently overwritten by the dst-type LOCAL rules for redirected traffic.
	r.rules[ruleKey] = r.conn.InsertRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameManglePrerouting],
		Exprs:    exprs,
		UserData: []byte(ruleKey),
	})

	return nil
}

// addPostroutingRules adds the masquerade rules
func (r *router) addPostroutingRules() {
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
// TODO: Add IPv6 support
func (r *router) addMSSClampingRules() error {
	mss := r.mtu - ipTCPHeaderMinSize

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

// addLegacyRouteRule adds a legacy routing rule for mgmt servers pre route acls
func (r *router) addLegacyRouteRule(pair firewall.RouterPair) error {
	sourceExp, err := r.applyNetwork(pair.Source, nil, true)
	if err != nil {
		return fmt.Errorf("apply source: %w", err)
	}

	destExp, err := r.applyNetwork(pair.Destination, nil, false)
	if err != nil {
		return fmt.Errorf("apply destination: %w", err)
	}

	exprs := []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	exprs = append(exprs, sourceExp...)
	exprs = append(exprs, destExp...)

	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	if _, exists := r.rules[ruleKey]; exists {
		if err := r.removeLegacyRouteRule(pair); err != nil {
			return fmt.Errorf("remove legacy routing rule: %w", err)
		}
	}

	r.rules[ruleKey] = r.conn.AddRule(&nftables.Rule{
		Table:    r.workTable,
		Chain:    r.chains[chainNameRoutingFw],
		Exprs:    exprs,
		UserData: []byte(ruleKey),
	})
	return nil
}

// removeLegacyRouteRule removes a legacy routing rule for mgmt servers pre route acls
func (r *router) removeLegacyRouteRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.ForwardingFormat, pair)

	rule, exists := r.rules[ruleKey]
	if !exists {
		return nil
	}

	if rule.Handle == 0 {
		log.Warnf("legacy forwarding rule %s has no handle, removing stale entry", ruleKey)
		if err := r.decrementSetCounter(rule); err != nil {
			log.Warnf("decrement set counter for stale rule %s: %v", ruleKey, err)
		}
		delete(r.rules, ruleKey)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("remove legacy forwarding rule %s -> %s: %w", pair.Source, pair.Destination, err)
	}

	log.Debugf("removed legacy forwarding rule %s -> %s", pair.Source, pair.Destination)

	delete(r.rules, ruleKey)

	if err := r.decrementSetCounter(rule); err != nil {
		return fmt.Errorf("decrement set counter: %w", err)
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
// This method also adds INPUT chain rules to allow traffic to the local interface.
func (r *router) acceptForwardRules() error {
	var merr *multierror.Error

	if err := r.acceptFilterTableRules(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.acceptExternalChainsRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("add accept rules to external chains: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) acceptFilterTableRules() error {
	if r.filterTable == nil {
		return nil
	}

	fw := "iptables"

	defer func() {
		log.Debugf("Used %s to add accept forward and input rules", fw)
	}()

	// Try iptables first and fallback to nftables if iptables is not available
	ipt, err := iptables.New()
	if err != nil {
		// iptables is not available but the filter table exists
		log.Warnf("Will use nftables to manipulate the filter table because iptables is not available: %v", err)

		fw = "nftables"
		return r.acceptFilterRulesNftables(r.filterTable)
	}

	return r.acceptFilterRulesIptables(ipt)
}

func (r *router) acceptFilterRulesIptables(ipt *iptables.IPTables) error {
	var merr *multierror.Error

	for _, rule := range r.getAcceptForwardRules() {
		if err := ipt.Insert("filter", chainNameForward, 1, rule...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add iptables forward rule: %v", err))
		} else {
			log.Debugf("added iptables forward rule: %v", rule)
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

func (r *router) getAcceptForwardRules() [][]string {
	intf := r.wgIface.Name()
	return [][]string{
		{"-i", intf, "-j", "ACCEPT"},
		{"-o", intf, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
}

func (r *router) getAcceptInputRule() []string {
	return []string{"-i", r.wgIface.Name(), "-j", "ACCEPT"}
}

// acceptFilterRulesNftables adds accept rules to the ip filter table using nftables.
// This is used when iptables is not available.
func (r *router) acceptFilterRulesNftables(table *nftables.Table) error {
	intf := ifname(r.wgIface.Name())

	forwardChain := &nftables.Chain{
		Name:     chainNameForward,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	}
	r.insertForwardAcceptRules(forwardChain, intf)

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
func (r *router) acceptExternalChainsRules() error {
	chains := r.findExternalChains()
	if len(chains) == 0 {
		return nil
	}

	intf := ifname(r.wgIface.Name())

	for _, chain := range chains {
		if chain.Hooknum == nil {
			log.Debugf("skipping external chain %s/%s: hooknum is nil", chain.Table.Name, chain.Name)
			continue
		}

		log.Debugf("adding accept rules to external %s chain: %s %s/%s",
			hookName(chain.Hooknum), familyName(chain.Table.Family), chain.Table.Name, chain.Name)

		switch *chain.Hooknum {
		case *nftables.ChainHookForward:
			r.insertForwardAcceptRules(chain, intf)
		case *nftables.ChainHookInput:
			r.insertInputAcceptRule(chain, intf)
		}
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush external chain rules: %w", err)
	}

	return nil
}

func (r *router) insertForwardAcceptRules(chain *nftables.Chain, intf []byte) {
	iifRule := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
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
	oifRule := &nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    append(oifExprs, getEstablishedExprs(2)...),
		UserData: []byte(userDataAcceptForwardRuleOif),
	}
	r.conn.InsertRule(oifRule)
}

func (r *router) insertInputAcceptRule(chain *nftables.Chain, intf []byte) {
	inputRule := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
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
		UserData: []byte(userDataAcceptInputRule),
	}
	r.conn.InsertRule(inputRule)
}

func (r *router) removeAcceptFilterRules() error {
	var merr *multierror.Error

	if err := r.removeFilterTableRules(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.removeExternalChainsRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove external chain rules: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) removeFilterTableRules() error {
	if r.filterTable == nil {
		return nil
	}

	ipt, err := iptables.New()
	if err != nil {
		log.Debugf("iptables not available, using nftables to remove filter rules: %v", err)
		return r.removeAcceptRulesFromTable(r.filterTable)
	}

	return r.removeAcceptFilterRulesIptables(ipt)
}

func (r *router) removeAcceptRulesFromTable(table *nftables.Table) error {
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

func (r *router) removeAcceptRulesFromChain(table *nftables.Table, chain *nftables.Chain) error {
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
func (r *router) removeExternalChainsRules() error {
	chains := r.findExternalChains()
	if len(chains) == 0 {
		return nil
	}

	for _, chain := range chains {
		if err := r.removeAcceptRulesFromChain(chain.Table, chain); err != nil {
			log.Warnf("remove rules from external chain %s/%s: %v", chain.Table.Name, chain.Name, err)
		}
	}

	return r.conn.Flush()
}

// findExternalChains scans for chains from non-netbird tables that have FORWARD or INPUT hooks.
// This is used both at startup (to know where to add rules) and at cleanup (to ensure deterministic removal).
func (r *router) findExternalChains() []*nftables.Chain {
	var chains []*nftables.Chain

	families := []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyINet}

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

func (r *router) isExternalChain(chain *nftables.Chain) bool {
	if r.workTable != nil && chain.Table.Name == r.workTable.Name {
		return false
	}

	// Skip all iptables-managed tables in the ip family
	if chain.Table.Family == nftables.TableFamilyIPv4 && isIptablesTable(chain.Table.Name) {
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

func (r *router) removeAcceptFilterRulesIptables(ipt *iptables.IPTables) error {
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

// RemoveNatRule removes the prerouting mark rule
func (r *router) RemoveNatRule(pair firewall.RouterPair) error {
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

func (r *router) removeNatRule(pair firewall.RouterPair) error {
	ruleKey := firewall.GenKey(firewall.PreroutingFormat, pair)

	rule, exists := r.rules[ruleKey]
	if !exists {
		log.Debugf("prerouting rule %s not found", ruleKey)
		return nil
	}

	if rule.Handle == 0 {
		log.Warnf("prerouting rule %s has no handle, removing stale entry", ruleKey)
		if err := r.decrementSetCounter(rule); err != nil {
			log.Warnf("decrement set counter for stale rule %s: %v", ruleKey, err)
		}
		delete(r.rules, ruleKey)
		return nil
	}

	if err := r.conn.DelRule(rule); err != nil {
		return fmt.Errorf("remove prerouting rule %s -> %s: %w", pair.Source, pair.Destination, err)
	}

	log.Debugf("removed prerouting rule %s -> %s", pair.Source, pair.Destination)

	delete(r.rules, ruleKey)

	if err := r.decrementSetCounter(rule); err != nil {
		return fmt.Errorf("decrement set counter: %w", err)
	}

	return nil
}

// refreshRulesMap rebuilds the rule map from the kernel. This removes stale entries
// (e.g. from failed flushes) and updates handles for all existing rules.
func (r *router) refreshRulesMap() error {
	var merr *multierror.Error
	newRules := make(map[string]*nftables.Rule)
	for _, chain := range r.chains {
		rules, err := r.conn.GetRules(chain.Table, chain)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("list rules for chain %s: %w", chain.Name, err))
			// preserve existing entries for this chain since we can't verify their state
			for k, v := range r.rules {
				if v.Chain != nil && v.Chain.Name == chain.Name {
					newRules[k] = v
				}
			}
			continue
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				newRules[string(rule.UserData)] = rule
			}
		}
	}
	r.rules = newRules
	return nberrors.FormatErrorOrNil(merr)
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
	var needsFlush bool

	if dnatRule, exists := r.rules[ruleKey+dnatSuffix]; exists {
		if dnatRule.Handle == 0 {
			log.Warnf("dnat rule %s has no handle, removing stale entry", ruleKey+dnatSuffix)
			delete(r.rules, ruleKey+dnatSuffix)
		} else if err := r.conn.DelRule(dnatRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete dnat rule: %w", err))
		} else {
			needsFlush = true
		}
	}

	if masqRule, exists := r.rules[ruleKey+snatSuffix]; exists {
		if masqRule.Handle == 0 {
			log.Warnf("snat rule %s has no handle, removing stale entry", ruleKey+snatSuffix)
			delete(r.rules, ruleKey+snatSuffix)
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

	if merr == nil {
		delete(r.rules, ruleKey+dnatSuffix)
		delete(r.rules, ruleKey+snatSuffix)
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *router) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	nfset, err := r.conn.GetSetByName(r.workTable, set.HashedName())
	if err != nil {
		return fmt.Errorf("get set %s: %w", set.HashedName(), err)
	}

	elements := convertPrefixesToSet(prefixes)
	if err := r.conn.SetAddElements(nfset, elements); err != nil {
		return fmt.Errorf("add elements to set %s: %w", set.HashedName(), err)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	log.Debugf("updated set %s with prefixes %v", set.HashedName(), prefixes)

	return nil
}

// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services.
func (r *router) AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	ruleID := fmt.Sprintf("inbound-dnat-%s-%s-%d-%d", localAddr.String(), protocol, sourcePort, targetPort)

	if _, exists := r.rules[ruleID]; exists {
		return nil
	}

	protoNum, err := protoToInt(protocol)
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
			Data:     binaryutil.BigEndian.PutUint16(sourcePort),
		},
	}

	exprs = append(exprs, applyPrefix(netip.PrefixFrom(localAddr, 32), false)...)

	exprs = append(exprs,
		&expr.Immediate{
			Register: 1,
			Data:     localAddr.AsSlice(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(targetPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyIPv4),
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
func (r *router) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	if err := r.refreshRulesMap(); err != nil {
		return fmt.Errorf(refreshRulesMapError, err)
	}

	ruleID := fmt.Sprintf("inbound-dnat-%s-%s-%d-%d", localAddr.String(), protocol, sourcePort, targetPort)

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

// applyNetwork generates nftables expressions for networks (CIDR) or sets
func (r *router) applyNetwork(
	network firewall.Network,
	setPrefixes []netip.Prefix,
	isSource bool,
) ([]expr.Any, error) {
	if network.IsSet() {
		exprs, err := r.getIpSet(network.Set, setPrefixes, isSource)
		if err != nil {
			return nil, fmt.Errorf("source: %w", err)
		}
		return exprs, nil
	}

	if network.IsPrefix() {
		return applyPrefix(network.Prefix, isSource), nil
	}

	return nil, nil
}

// applyPrefix generates nftables expressions for a CIDR prefix
func applyPrefix(prefix netip.Prefix, isSource bool) []expr.Any {
	// dst offset
	offset := uint32(16)
	if isSource {
		// src offset
		offset = 12
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

func getIpSetExprs(ref refcounter.Ref[*nftables.Set], isSource bool) ([]expr.Any, error) {

	// dst offset
	offset := uint32(16)
	if isSource {
		// src offset
		offset = 12
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        ref.Out.Name,
			SetID:          ref.Out.ID,
		},
	}, nil
}
