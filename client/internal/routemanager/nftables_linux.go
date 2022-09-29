package routemanager

import (
	"context"
	"fmt"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"net"
	"net/netip"
	"sync"
)
import "github.com/google/nftables"

const (
	nftablesTable                  = "netbird-rt"
	nftablesRoutingForwardingChain = "netbird-rt-fwd"
	nftablesRoutingNatChain        = "netbird-rt-nat"
)

// constants needed to create nftable rules
const (
	ipv4Len                  = 4
	ipv4SrcOffset            = 12
	ipv4DestOffset           = 16
	ipv6Len                  = 16
	ipv6SrcOffset            = 8
	ipv6DestOffset           = 24
	exprDirectionSource      = "source"
	exprDirectionDestination = "destination"
)

// some presets for building nftable rules
var (
	zeroXor = binaryutil.NativeEndian.PutUint32(0)

	zeroXor6 = append(binaryutil.NativeEndian.PutUint64(0), binaryutil.NativeEndian.PutUint64(0)...)

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
	ctx       context.Context
	stop      context.CancelFunc
	conn      *nftables.Conn
	tableIPv4 *nftables.Table
	tableIPv6 *nftables.Table
	chains    map[string]map[string]*nftables.Chain
	rules     map[string]*nftables.Rule
	mux       sync.Mutex
}

// CleanRoutingRules cleans existing nftables rules from the system
func (n *nftablesManager) CleanRoutingRules() {
	n.mux.Lock()
	defer n.mux.Unlock()
	log.Debug("flushing tables")
	if n.tableIPv4 != nil && n.tableIPv6 != nil {
		n.conn.FlushTable(n.tableIPv6)
		n.conn.FlushTable(n.tableIPv4)
	}
	log.Debugf("flushing tables result in: %v error", n.conn.Flush())
}

// RestoreOrCreateContainers restores existing nftables containers (tables and chains)
// if they don't exist, we create them
func (n *nftablesManager) RestoreOrCreateContainers() error {
	n.mux.Lock()
	defer n.mux.Unlock()

	if n.tableIPv6 != nil && n.tableIPv4 != nil {
		log.Debugf("nftables: containers already restored, skipping")
		return nil
	}

	tables, err := n.conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables: unable to list tables: %v", err)
	}

	for _, table := range tables {
		if table.Name == nftablesTable {
			if table.Family == nftables.TableFamilyIPv4 {
				n.tableIPv4 = table
				continue
			}
			n.tableIPv6 = table
		}
	}

	if n.tableIPv4 == nil {
		n.tableIPv4 = n.conn.AddTable(&nftables.Table{
			Name:   nftablesTable,
			Family: nftables.TableFamilyIPv4,
		})
	}

	if n.tableIPv6 == nil {
		n.tableIPv6 = n.conn.AddTable(&nftables.Table{
			Name:   nftablesTable,
			Family: nftables.TableFamilyIPv6,
		})
	}

	chains, err := n.conn.ListChains()
	if err != nil {
		return fmt.Errorf("nftables: unable to list chains: %v", err)
	}

	n.chains[ipv4] = make(map[string]*nftables.Chain)
	n.chains[ipv6] = make(map[string]*nftables.Chain)

	for _, chain := range chains {
		switch {
		case chain.Table.Name == nftablesTable && chain.Table.Family == nftables.TableFamilyIPv4:
			n.chains[ipv4][chain.Name] = chain
		case chain.Table.Name == nftablesTable && chain.Table.Family == nftables.TableFamilyIPv6:
			n.chains[ipv6][chain.Name] = chain
		}
	}

	if _, found := n.chains[ipv4][nftablesRoutingForwardingChain]; !found {
		n.chains[ipv4][nftablesRoutingForwardingChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingForwardingChain,
			Table:    n.tableIPv4,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityNATDest + 1,
			Type:     nftables.ChainTypeFilter,
		})
	}

	if _, found := n.chains[ipv4][nftablesRoutingNatChain]; !found {
		n.chains[ipv4][nftablesRoutingNatChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingNatChain,
			Table:    n.tableIPv4,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource - 1,
			Type:     nftables.ChainTypeNAT,
		})
	}

	if _, found := n.chains[ipv6][nftablesRoutingForwardingChain]; !found {
		n.chains[ipv6][nftablesRoutingForwardingChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingForwardingChain,
			Table:    n.tableIPv6,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityNATDest + 1,
			Type:     nftables.ChainTypeFilter,
		})
	}

	if _, found := n.chains[ipv6][nftablesRoutingNatChain]; !found {
		n.chains[ipv6][nftablesRoutingNatChain] = n.conn.AddChain(&nftables.Chain{
			Name:     nftablesRoutingNatChain,
			Table:    n.tableIPv6,
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
	for _, registeredChains := range n.chains {
		for _, chain := range registeredChains {
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
	}
	return nil
}

// checkOrCreateDefaultForwardingRules checks if the default forwarding rules are enabled
func (n *nftablesManager) checkOrCreateDefaultForwardingRules() {
	_, foundIPv4 := n.rules[ipv4Forwarding]
	if !foundIPv4 {
		n.rules[ipv4Forwarding] = n.conn.AddRule(&nftables.Rule{
			Table:    n.tableIPv4,
			Chain:    n.chains[ipv4][nftablesRoutingForwardingChain],
			Exprs:    exprAllowRelatedEstablished,
			UserData: []byte(ipv4Forwarding),
		})
	}

	_, foundIPv6 := n.rules[ipv6Forwarding]
	if !foundIPv6 {
		n.rules[ipv6Forwarding] = n.conn.AddRule(&nftables.Rule{
			Table:    n.tableIPv6,
			Chain:    n.chains[ipv6][nftablesRoutingForwardingChain],
			Exprs:    exprAllowRelatedEstablished,
			UserData: []byte(ipv6Forwarding),
		})
	}
}

// InsertRoutingRules inserts a nftable rule pair to the forwarding chain and if enabled, to the nat chain
func (n *nftablesManager) InsertRoutingRules(pair routerPair) error {
	n.mux.Lock()
	defer n.mux.Unlock()

	n.insertRoutingRule(forwardingFormat, nftablesRoutingForwardingChain, pair, false)
	n.insertRoutingRule(inForwardingFormat, nftablesRoutingForwardingChain, getInPair(pair), false)

	if pair.masquerade {
		n.insertRoutingRule(natFormat, nftablesRoutingNatChain, pair, true)
		n.insertRoutingRule(inNatFormat, nftablesRoutingNatChain, getInPair(pair), true)
	}

	err := n.conn.Flush()
	if err != nil {
		return fmt.Errorf("nftables: unable to insert rules for %s: %v", pair.destination, err)
	}
	return nil
}

// insertRoutingRule inserts a nftable rule to the conn client flush queue
func (n *nftablesManager) insertRoutingRule(format, chain string, pair routerPair, isNat bool) {

	prefix := netip.MustParsePrefix(pair.source)

	sourceExp := generateCIDRMatcherExpressions("source", pair.source)
	destExp := generateCIDRMatcherExpressions("destination", pair.destination)

	var expression []expr.Any
	if isNat {
		expression = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
	} else {
		expression = append(sourceExp, append(destExp, exprCounterAccept...)...)
	}

	ruleKey := genKey(format, pair.ID)

	if prefix.Addr().Unmap().Is4() {
		n.rules[ruleKey] = n.conn.InsertRule(&nftables.Rule{
			Table:    n.tableIPv4,
			Chain:    n.chains[ipv4][chain],
			Exprs:    expression,
			UserData: []byte(ruleKey),
		})
	} else {
		n.rules[ruleKey] = n.conn.InsertRule(&nftables.Rule{
			Table:    n.tableIPv6,
			Chain:    n.chains[ipv6][chain],
			Exprs:    expression,
			UserData: []byte(ruleKey),
		})
	}
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

// getPayloadDirectives get expression directives based on ip version and direction
func getPayloadDirectives(direction string, isIPv4 bool, isIPv6 bool) (uint32, uint32, []byte) {
	switch {
	case direction == exprDirectionSource && isIPv4:
		return ipv4SrcOffset, ipv4Len, zeroXor
	case direction == exprDirectionDestination && isIPv4:
		return ipv4DestOffset, ipv4Len, zeroXor
	case direction == exprDirectionSource && isIPv6:
		return ipv6SrcOffset, ipv6Len, zeroXor6
	case direction == exprDirectionDestination && isIPv6:
		return ipv6DestOffset, ipv6Len, zeroXor6
	default:
		panic("no matched payload directive")
	}
}

// generateCIDRMatcherExpressions generates nftables expressions that matches a CIDR
func generateCIDRMatcherExpressions(direction string, cidr string) []expr.Any {
	ip, network, _ := net.ParseCIDR(cidr)
	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()

	offSet, packetLen, zeroXor := getPayloadDirectives(direction, add.Is4(), add.Is6())

	return []expr.Any{
		// fetch src add
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offSet,
			Len:          packetLen,
		},
		// net mask
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            packetLen,
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
