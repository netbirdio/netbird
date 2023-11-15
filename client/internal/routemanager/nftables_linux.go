//go:build !android

package routemanager

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
)

const (
	nftablesTable                  = "netbird-rt"
	nftablesRoutingForwardingChain = "netbird-rt-fwd"
	nftablesRoutingNatChain        = "netbird-rt-nat"

	userDataAcceptForwardRuleSrc = "frwacceptsrc"
	userDataAcceptForwardRuleDst = "frwacceptdst"
)

// constants needed to create nftable rules
const (
	ipv4Len             = 4
	ipv4SrcOffset       = 12
	ipv4DestOffset      = 16
	exprDirectionSource = "source"
)

// some presets for building nftable rules
var (
	zeroXor = binaryutil.NativeEndian.PutUint32(0)

	exprAllowRelatedEstablished = []expr.Any{
		&expr.Ct{
			Register:       1,
			SourceRegister: false,
			Key:            0,
		},
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            4,
			Mask:           []uint8{0x6, 0x0, 0x0, 0x0},
			Xor:            zeroXor,
		},
		&expr.Cmp{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	exprCounterAccept = []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}
)

type nftablesManager struct {
	ctx                 context.Context
	stop                context.CancelFunc
	conn                *nftables.Conn
	table               *nftables.Table
	chains              map[string]*nftables.Chain
	rules               map[string]*nftables.Rule
	filterTable         *nftables.Table
	defaultForwardRules []*nftables.Rule
	mux                 sync.Mutex
}

func newNFTablesManager(parentCtx context.Context) *nftablesManager {
	ctx, cancel := context.WithCancel(parentCtx)

	return &nftablesManager{
		ctx:                 ctx,
		stop:                cancel,
		conn:                &nftables.Conn{},
		chains:              make(map[string]*nftables.Chain),
		rules:               make(map[string]*nftables.Rule),
		defaultForwardRules: make([]*nftables.Rule, 2),
	}
}

// CleanRoutingRules cleans existing nftables rules from the system
func (n *nftablesManager) CleanRoutingRules() {
	n.mux.Lock()
	defer n.mux.Unlock()
	log.Debug("flushing tables")
	if n.table != nil {
		n.conn.FlushTable(n.table)
	}

	if n.defaultForwardRules[0] != nil {
		err := n.eraseDefaultForwardRule()
		if err != nil {
			log.Errorf("failed to delete forward rule: %s", err)
		}
	}
	log.Debugf("flushing tables result in: %v error", n.conn.Flush())
}

// RestoreOrCreateContainers restores existing nftables containers (tables and chains)
// if they don't exist, we create them
func (n *nftablesManager) RestoreOrCreateContainers() error {
	n.mux.Lock()
	defer n.mux.Unlock()

	if n.table != nil {
		log.Debugf("nftables: containers already restored, skipping")
		return nil
	}

	tables, err := n.conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables: unable to list tables: %v", err)
	}

	for _, table := range tables {
		if table.Name == "filter" && table.Family == nftables.TableFamilyIPv4 {
			log.Debugf("nftables: found filter table for ipv4")
			n.filterTable = table
			continue
		}
		if table.Name == nftablesTable && table.Family == nftables.TableFamilyIPv4 {
			n.table = table
			continue
		}
	}

	if n.table == nil {
		n.table = n.conn.AddTable(&nftables.Table{
			Name:   nftablesTable,
			Family: nftables.TableFamilyIPv4,
		})
	}

	chains, err := n.conn.ListChains()
	if err != nil {
		return fmt.Errorf("nftables: unable to list chains: %v", err)
	}

	n.chains = make(map[string]*nftables.Chain)

	for _, chain := range chains {
		if chain.Table.Name == nftablesTable && chain.Table.Family == nftables.TableFamilyIPv4 {
			n.chains[chain.Name] = chain
		}
	}

	if _, found := n.chains[nftablesRoutingForwardingChain]; !found {
		n.chains[nftablesRoutingForwardingChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingForwardingChain,
			Table:    n.table,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityNATDest + 1,
			Type:     nftables.ChainTypeFilter,
		})
	}

	if _, found := n.chains[nftablesRoutingNatChain]; !found {
		n.chains[nftablesRoutingNatChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingNatChain,
			Table:    n.table,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource - 1,
			Type:     nftables.ChainTypeNAT,
		})
	}

	err = n.refreshRulesMap()
	if err != nil {
		return err
	}

	n.checkOrCreateDefaultForwardingRules()
	err = n.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: unable to initialize table: %v", err)
	}
	return nil
}

// refreshRulesMap refreshes the rule map with the latest rules. this is useful to avoid
// duplicates and to get missing attributes that we don't have when adding new rules
func (n *nftablesManager) refreshRulesMap() error {
	for _, chain := range n.chains {
		rules, err := n.conn.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("nftables: unable to list rules: %v", err)
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				n.rules[string(rule.UserData)] = rule
			}
		}
	}
	return nil
}

func (n *nftablesManager) eraseDefaultForwardRule() error {
	if n.defaultForwardRules[0] == nil {
		return nil
	}

	err := n.refreshDefaultForwardRule()
	if err != nil {
		return err
	}

	for i, r := range n.defaultForwardRules {
		err = n.conn.DelRule(r)
		if err != nil {
			log.Errorf("failed to delete forward rule (%d): %s", i, err)
		}
		n.defaultForwardRules[i] = nil
	}
	return nil
}

func (n *nftablesManager) refreshDefaultForwardRule() error {
	rules, err := n.conn.GetRules(n.defaultForwardRules[0].Table, n.defaultForwardRules[0].Chain)
	if err != nil {
		return fmt.Errorf("unable to list rules in forward chain: %s", err)
	}

	found := false
	for i, r := range n.defaultForwardRules {
		for _, rule := range rules {
			if string(rule.UserData) == string(r.UserData) {
				n.defaultForwardRules[i] = rule
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("unable to find forward accept rule")
	}

	return nil
}

func (n *nftablesManager) acceptForwardRule(sourceNetwork string) error {
	src := generateCIDRMatcherExpressions("source", sourceNetwork)
	dst := generateCIDRMatcherExpressions("destination", "0.0.0.0/0")

	var exprs []expr.Any
	exprs = append(src, append(dst, &expr.Verdict{ //nolint:gocritic
		Kind: expr.VerdictAccept,
	})...)

	r := &nftables.Rule{
		Table: n.filterTable,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    n.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs:    exprs,
		UserData: []byte(userDataAcceptForwardRuleSrc),
	}

	n.defaultForwardRules[0] = n.conn.AddRule(r)

	src = generateCIDRMatcherExpressions("source", "0.0.0.0/0")
	dst = generateCIDRMatcherExpressions("destination", sourceNetwork)

	exprs = append(src, append(dst, &expr.Verdict{ //nolint:gocritic
		Kind: expr.VerdictAccept,
	})...)

	r = &nftables.Rule{
		Table: n.filterTable,
		Chain: &nftables.Chain{
			Name:     "FORWARD",
			Table:    n.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		},
		Exprs:    exprs,
		UserData: []byte(userDataAcceptForwardRuleDst),
	}

	n.defaultForwardRules[1] = n.conn.AddRule(r)
	return nil
}

// checkOrCreateDefaultForwardingRules checks if the default forwarding rules are enabled
func (n *nftablesManager) checkOrCreateDefaultForwardingRules() {
	_, ok := n.rules[ipv4Forwarding]
	if ok {
		return
	}
	n.rules[ipv4Forwarding] = n.conn.AddRule(&nftables.Rule{
		Table:    n.table,
		Chain:    n.chains[nftablesRoutingForwardingChain],
		Exprs:    exprAllowRelatedEstablished,
		UserData: []byte(ipv4Forwarding),
	})
}

// InsertRoutingRules inserts a nftable rule pair to the forwarding chain and if enabled, to the nat chain
func (n *nftablesManager) InsertRoutingRules(pair routerPair) error {
	n.mux.Lock()
	defer n.mux.Unlock()

	err := n.refreshRulesMap()
	if err != nil {
		return err
	}

	err = n.insertRoutingRule(forwardingFormat, nftablesRoutingForwardingChain, pair, false)
	if err != nil {
		return err
	}
	err = n.insertRoutingRule(inForwardingFormat, nftablesRoutingForwardingChain, getInPair(pair), false)
	if err != nil {
		return err
	}

	if pair.masquerade {
		err = n.insertRoutingRule(natFormat, nftablesRoutingNatChain, pair, true)
		if err != nil {
			return err
		}
		err = n.insertRoutingRule(inNatFormat, nftablesRoutingNatChain, getInPair(pair), true)
		if err != nil {
			return err
		}
	}

	if n.defaultForwardRules[0] == nil && n.filterTable != nil {
		err = n.acceptForwardRule(pair.source)
		if err != nil {
			log.Errorf("unable to create default forward rule: %s", err)
		}
		log.Debugf("default accept forward rule added")
	}

	err = n.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: unable to insert rules for %s: %v", pair.destination, err)
	}
	return nil
}

// insertRoutingRule inserts a nftable rule to the conn client flush queue
func (n *nftablesManager) insertRoutingRule(format, chain string, pair routerPair, isNat bool) error {
	sourceExp := generateCIDRMatcherExpressions("source", pair.source)
	destExp := generateCIDRMatcherExpressions("destination", pair.destination)

	var expression []expr.Any
	if isNat {
		expression = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) //nolint:gocritic
	} else {
		expression = append(sourceExp, append(destExp, exprCounterAccept...)...) //nolint:gocritic
	}

	ruleKey := genKey(format, pair.ID)

	_, exists := n.rules[ruleKey]
	if exists {
		err := n.removeRoutingRule(format, pair)
		if err != nil {
			return err
		}
	}

	n.rules[ruleKey] = n.conn.InsertRule(&nftables.Rule{
		Table:    n.table,
		Chain:    n.chains[chain],
		Exprs:    expression,
		UserData: []byte(ruleKey),
	})
	return nil
}

// RemoveRoutingRules removes a nftable rule pair from forwarding and nat chains
func (n *nftablesManager) RemoveRoutingRules(pair routerPair) error {
	n.mux.Lock()
	defer n.mux.Unlock()

	err := n.refreshRulesMap()
	if err != nil {
		return err
	}

	err = n.removeRoutingRule(forwardingFormat, pair)
	if err != nil {
		return err
	}

	err = n.removeRoutingRule(inForwardingFormat, getInPair(pair))
	if err != nil {
		return err
	}

	err = n.removeRoutingRule(natFormat, pair)
	if err != nil {
		return err
	}

	err = n.removeRoutingRule(inNatFormat, getInPair(pair))
	if err != nil {
		return err
	}

	if len(n.rules) == 2 && n.defaultForwardRules[0] != nil {
		err := n.eraseDefaultForwardRule()
		if err != nil {
			log.Errorf("failed to delete default fwd rule: %s", err)
		}
	}

	err = n.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: received error while applying rule removal for %s: %v", pair.destination, err)
	}
	log.Debugf("nftables: removed rules for %s", pair.destination)
	return nil
}

// removeRoutingRule add a nftable rule to the removal queue and delete from rules map
func (n *nftablesManager) removeRoutingRule(format string, pair routerPair) error {
	ruleKey := genKey(format, pair.ID)

	rule, found := n.rules[ruleKey]
	if found {
		ruleType := "forwarding"
		if rule.Chain.Type == nftables.ChainTypeNAT {
			ruleType = "nat"
		}

		err := n.conn.DelRule(rule)
		if err != nil {
			return fmt.Errorf("nftables: unable to remove %s rule for %s: %v", ruleType, pair.destination, err)
		}

		log.Debugf("nftables: removing %s rule for %s", ruleType, pair.destination)

		delete(n.rules, ruleKey)
	}
	return nil
}

// generateCIDRMatcherExpressions generates nftables expressions that matches a CIDR
func generateCIDRMatcherExpressions(direction string, cidr string) []expr.Any {
	ip, network, _ := net.ParseCIDR(cidr)
	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()

	var offSet uint32
	if direction == exprDirectionSource {
		offSet = ipv4SrcOffset
	} else {
		offSet = ipv4DestOffset
	}

	return []expr.Any{
		// fetch src add
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offSet,
			Len:          ipv4Len,
		},
		// net mask
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            ipv4Len,
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
