package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	chainNameRouteingFw = "netbird-rt-fwd"
	chainNameRoutingNat = "netbird-rt-nat"

	userDataAcceptForwardRuleSrc = "frwacceptsrc"
	userDataAcceptForwardRuleDst = "frwacceptdst"
)

// some presets for building nftable rules
var (
	zeroXor  = binaryutil.NativeEndian.PutUint32(0)
	zeroXor6 = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	exprCounterAccept = []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	errFilterTableNotFound = fmt.Errorf("nftables: 'filter' table not found")
)

type router struct {
	ctx          context.Context
	stop         context.CancelFunc
	conn         *nftables.Conn
	workTable    *nftables.Table
	workTable6   *nftables.Table
	filterTable  *nftables.Table
	filterTable6 *nftables.Table
	chains       map[string]*nftables.Chain
	chains6      map[string]*nftables.Chain
	// rules is useful to avoid duplicates and to get missing attributes that we don't have when adding new rules
	rules                     map[string]*nftables.Rule
	rules6                    map[string]*nftables.Rule
	isDefaultFwdRulesEnabled  bool
	isDefaultFwdRulesEnabled6 bool
}

func newRouter(parentCtx context.Context, workTable *nftables.Table, workTable6 *nftables.Table) (*router, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	r := &router{
		ctx:        ctx,
		stop:       cancel,
		conn:       &nftables.Conn{},
		workTable:  workTable,
		workTable6: workTable6,
		chains:     make(map[string]*nftables.Chain),
		chains6:    make(map[string]*nftables.Chain),
		rules:      make(map[string]*nftables.Rule),
		rules6:     make(map[string]*nftables.Rule),
	}

	var err error
	r.filterTable, r.filterTable6, err = r.loadFilterTables()
	if err != nil {
		if errors.Is(err, errFilterTableNotFound) {
			log.Warnf("table 'filter' not found for forward rules for one of the supported address families-")
		} else {
			return nil, err
		}
	}

	err = r.cleanUpDefaultForwardRules(false)
	if err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	err = r.cleanUpDefaultForwardRules(true)
	if err != nil {
		log.Errorf("failed to clean up rules from IPv6 FORWARD chain: %s", err)
	}

	err = r.createContainers(false)
	if err != nil {
		log.Errorf("failed to create containers for route: %s", err)
	}

	if r.workTable6 != nil {
		err = r.createContainers(true)
		if err != nil {
			log.Errorf("failed to create v6 containers for route: %s", err)
		}
	}

	return r, err
}

func (r *router) RouteingFwChainName() string {
	return chainNameRouteingFw
}

// ResetForwardRules cleans existing nftables default forward rules from the system
func (r *router) ResetForwardRules() {
	err := r.cleanUpDefaultForwardRules(false)
	if err != nil {
		log.Errorf("failed to reset forward rules: %s", err)
	}
	err = r.cleanUpDefaultForwardRules(true)
	if err != nil {
		log.Errorf("failed to reset forward rules: %s", err)
	}
}

func (r *router) RestoreAfterV6Reset(newWorktable6 *nftables.Table) error {
	r.workTable6 = newWorktable6
	if newWorktable6 != nil {

		err := r.cleanUpDefaultForwardRules(true)
		if err != nil {
			log.Errorf("failed to clean up rules from IPv6 FORWARD chain: %s", err)
		}

		err = r.createContainers(true)
		if err != nil {
			return err
		}

		for name, rule := range r.rules6 {
			rule = &nftables.Rule{
				Table:    r.workTable6,
				Chain:    r.chains6[rule.Chain.Name],
				Exprs:    rule.Exprs,
				UserData: rule.UserData,
			}
			r.rules6[name] = r.conn.AddRule(rule)
		}
	}
	return r.conn.Flush()
}

func (r *router) loadFilterTables() (*nftables.Table, *nftables.Table, error) {
	tables, err := r.conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, nil, fmt.Errorf("nftables: unable to list tables: %v", err)
	}

	var table4 *nftables.Table = nil
	for _, table := range tables {
		if table.Name == "filter" {
			table4 = table
			break
		}
	}

	var table6 *nftables.Table = nil
	tables, err = r.conn.ListTablesOfFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return nil, nil, fmt.Errorf("nftables: unable to list tables: %v", err)
	}
	for _, table := range tables {
		if table.Name == "filter" {
			table6 = table
			break
		}
	}

	err = nil
	if table4 == nil || table6 == nil {
		err = errFilterTableNotFound
	}

	return table4, table6, err
}

func (r *router) createContainers(forV6 bool) error {
	workTable := r.workTable
	chainStorage := r.chains
	if forV6 {
		workTable = r.workTable6
		chainStorage = r.chains6
	}

	chainStorage[chainNameRouteingFw] = r.conn.AddChain(&nftables.Chain{
		Name:  chainNameRouteingFw,
		Table: workTable,
	})

	chainStorage[chainNameRoutingNat] = r.conn.AddChain(&nftables.Chain{
		Name:     chainNameRoutingNat,
		Table:    workTable,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource - 1,
		Type:     nftables.ChainTypeNAT,
	})

	err := r.refreshRulesMap(forV6)
	if err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	err = r.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: unable to initialize table: %v", err)
	}
	return nil
}

// InsertRoutingRules inserts a nftable rule pair to the forwarding chain and if enabled, to the nat chain
func (r *router) InsertRoutingRules(pair manager.RouterPair) error {
	parsedIp, _, _ := net.ParseCIDR(pair.Source)

	if parsedIp.To4() == nil && r.workTable6 == nil {
		return fmt.Errorf("nftables: attempted to add IPv6 routing rule even though IPv6 is not enabled for this host")
	}

	err := r.refreshRulesMap(parsedIp.To4() == nil)
	if err != nil {
		return err
	}

	err = r.insertRoutingRule(manager.ForwardingFormat, chainNameRouteingFw, pair, false)
	if err != nil {
		return err
	}
	err = r.insertRoutingRule(manager.InForwardingFormat, chainNameRouteingFw, manager.GetInPair(pair), false)
	if err != nil {
		return err
	}

	if pair.Masquerade {
		err = r.insertRoutingRule(manager.NatFormat, chainNameRoutingNat, pair, true)
		if err != nil {
			return err
		}
		err = r.insertRoutingRule(manager.InNatFormat, chainNameRoutingNat, manager.GetInPair(pair), true)
		if err != nil {
			return err
		}
	}

	filterTable := r.filterTable
	if parsedIp.To4() == nil {
		filterTable = r.filterTable6
	}
	if filterTable != nil && !r.isDefaultFwdRulesEnabled {
		log.Debugf("add default accept forward rule")
		r.acceptForwardRule(pair.Source)
	}

	err = r.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: unable to insert rules for %s: %v", pair.Destination, err)
	}
	return nil
}

// insertRoutingRule inserts a nftable rule to the conn client flush queue
func (r *router) insertRoutingRule(format, chainName string, pair manager.RouterPair, isNat bool) error {
	sourceExp := generateCIDRMatcherExpressions(true, pair.Source)
	destExp := generateCIDRMatcherExpressions(false, pair.Destination)

	var expression []expr.Any
	if isNat {
		expression = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) // nolint:gocritic
	} else {
		expression = append(sourceExp, append(destExp, exprCounterAccept...)...) // nolint:gocritic
	}

	ruleKey := manager.GenKey(format, pair.ID)

	parsedIp, _, _ := net.ParseCIDR(pair.Source)
	rules := r.rules
	if parsedIp.To4() == nil {
		rules = r.rules6
	}

	_, exists := rules[ruleKey]
	if exists {
		err := r.removeRoutingRule(format, pair)
		if err != nil {
			return err
		}
	}

	table, chain := r.workTable, r.chains[chainName]
	if parsedIp.To4() == nil {
		table, chain = r.workTable6, r.chains6[chainName]
	}

	newRule := r.conn.InsertRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    expression,
		UserData: []byte(ruleKey),
	})

	if parsedIp.To4() == nil {
		r.rules[ruleKey] = newRule
	} else {
		r.rules6[ruleKey] = newRule
	}
	return nil
}

func (r *router) acceptForwardRule(sourceNetwork string) {
	src := generateCIDRMatcherExpressions(true, sourceNetwork)
	dst := generateCIDRMatcherExpressions(false, "0.0.0.0/0")
	table := r.filterTable
	parsedIp, _, _ := net.ParseCIDR(sourceNetwork)
	if parsedIp.To4() == nil {
		dst = generateCIDRMatcherExpressions(false, "::/0")
		table = r.filterTable6
	}

	var exprs []expr.Any
	exprs = append(src, append(dst, &expr.Verdict{ // nolint:gocritic
		Kind: expr.VerdictAccept,
	})...)

	rule := &nftables.Rule{
		Table: table,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs:    exprs,
		UserData: []byte(userDataAcceptForwardRuleSrc),
	}

	r.conn.AddRule(rule)

	src = generateCIDRMatcherExpressions(true, "0.0.0.0/0")
	if parsedIp.To4() == nil {
		src = generateCIDRMatcherExpressions(true, "::/0")
	}
	dst = generateCIDRMatcherExpressions(false, sourceNetwork)

	exprs = append(src, append(dst, &expr.Verdict{ //nolint:gocritic
		Kind: expr.VerdictAccept,
	})...)

	rule = &nftables.Rule{
		Table: table,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs:    exprs,
		UserData: []byte(userDataAcceptForwardRuleDst),
	}
	r.conn.AddRule(rule)
	if parsedIp.To4() == nil {
		r.isDefaultFwdRulesEnabled6 = true
	} else {
		r.isDefaultFwdRulesEnabled = true
	}
}

// RemoveRoutingRules removes a nftable rule pair from forwarding and nat chains
func (r *router) RemoveRoutingRules(pair manager.RouterPair) error {
	parsedIp, _, _ := net.ParseCIDR(pair.Source)
	if parsedIp.To4() == nil && r.workTable6 == nil {
		return fmt.Errorf("nftables: attempted to remove IPv6 routing rule even though IPv6 is not enabled for this host")
	}

	err := r.refreshRulesMap(parsedIp.To4() == nil)
	if err != nil {
		return err
	}

	err = r.removeRoutingRule(manager.ForwardingFormat, pair)
	if err != nil {
		return err
	}

	err = r.removeRoutingRule(manager.InForwardingFormat, manager.GetInPair(pair))
	if err != nil {
		return err
	}

	err = r.removeRoutingRule(manager.NatFormat, pair)
	if err != nil {
		return err
	}

	err = r.removeRoutingRule(manager.InNatFormat, manager.GetInPair(pair))
	if err != nil {
		return err
	}

	rulesList := r.rules
	if parsedIp.To4() == nil {
		rulesList = r.rules6
	}
	if len(rulesList) == 0 {
		err := r.cleanUpDefaultForwardRules(parsedIp.To4() == nil)
		if err != nil {
			log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
		}
	}

	err = r.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: received error while applying rule removal for %s: %v", pair.Destination, err)
	}
	log.Debugf("nftables: removed rules for %s", pair.Destination)
	return nil
}

// removeRoutingRule add a nftable rule to the removal queue and delete from rules map
func (r *router) removeRoutingRule(format string, pair manager.RouterPair) error {
	ruleKey := manager.GenKey(format, pair.ID)

	parsedIp, _, _ := net.ParseCIDR(pair.Source)
	rules := r.rules
	if parsedIp.To4() == nil {
		rules = r.rules6
	}

	rule, found := rules[ruleKey]
	if found {
		ruleType := "forwarding"
		if rule.Chain.Type == nftables.ChainTypeNAT {
			ruleType = "nat"
		}

		err := r.conn.DelRule(rule)
		if err != nil {
			return fmt.Errorf("nftables: unable to remove %s rule for %s: %v", ruleType, pair.Destination, err)
		}

		log.Debugf("nftables: removing %s rule for %s", ruleType, pair.Destination)

		delete(rules, ruleKey)
	}
	return nil
}

// refreshRulesMap refreshes the rule map with the latest rules. this is useful to avoid
// duplicates and to get missing attributes that we don't have when adding new rules
func (r *router) refreshRulesMap(forV6 bool) error {
	chainList := r.chains
	if forV6 {
		chainList = r.chains6
	}
	for _, chain := range chainList {
		rules, err := r.conn.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("nftables: unable to list rules: %v", err)
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				if forV6 {
					r.rules6[string(rule.UserData)] = rule
				} else {
					r.rules[string(rule.UserData)] = rule
				}
			}
		}
	}
	return nil
}

func (r *router) cleanUpDefaultForwardRules(forV6 bool) error {
	tableFamily := nftables.TableFamilyIPv4
	filterTable := r.filterTable
	if forV6 {
		tableFamily = nftables.TableFamilyIPv6
		filterTable = r.filterTable6
	}

	if filterTable == nil {
		if forV6 {
			r.isDefaultFwdRulesEnabled6 = false
		} else {
			r.isDefaultFwdRulesEnabled = false
		}
		return nil
	}

	chains, err := r.conn.ListChainsOfTableFamily(tableFamily)
	if err != nil {
		return err
	}

	var rules []*nftables.Rule
	for _, chain := range chains {
		if chain.Table.Name != filterTable.Name {
			continue
		}
		if chain.Name != "FORWARD" {
			continue
		}

		rules, err = r.conn.GetRules(filterTable, chain)
		if err != nil {
			return err
		}
	}

	for _, rule := range rules {
		if bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleSrc)) || bytes.Equal(rule.UserData, []byte(userDataAcceptForwardRuleDst)) {
			err := r.conn.DelRule(rule)
			if err != nil {
				return err
			}
		}
	}

	if forV6 {
		r.isDefaultFwdRulesEnabled6 = false
	} else {
		r.isDefaultFwdRulesEnabled = false
	}
	return r.conn.Flush()
}

// generateCIDRMatcherExpressions generates nftables expressions that matches a CIDR
func generateCIDRMatcherExpressions(source bool, cidr string) []expr.Any {
	ip, network, _ := net.ParseCIDR(cidr)
	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()

	var offSet uint32
	if source {
		offSet = 12 // src offset
	} else {
		offSet = 16 // dst offset
	}
	addrLen := uint32(4)
	zeroXor := zeroXor

	if ip.To4() == nil {
		if source {
			offSet = 8 // src offset
		} else {
			offSet = 24 // dst offset
		}
		addrLen = 16
		zeroXor = zeroXor6
	}

	return []expr.Any{
		// fetch src add
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offSet,
			Len:          addrLen,
		},
		// net mask
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            addrLen,
			Mask:           network.Mask,
			Xor:            zeroXor,
		},
		// net address
		&expr.Cmp{
			Register: 1,
			Data:     add.AsSlice(),
		},
	}
}
