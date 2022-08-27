package routemanager

import (
	"context"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"net"
	"net/netip"
	"sync"
)
import "github.com/google/nftables"

const (
	NftablesTable                  = "netbird-rt"
	NftablesRoutingForwardingChain = "netbird-rt-fwd"
	NftablesRoutingNatChain        = "netbird-rt-nat"
)

const (
	Ipv4Len                  = 4
	Ipv4SrcOffset            = 12
	Ipv4DestOffset           = 16
	Ipv6Len                  = 16
	Ipv6SrcOffset            = 8
	Ipv6DestOffset           = 24
	ExprDirectionSource      = "source"
	ExprDirectionDestination = "destination"
)

var (
	ZeroXor = binaryutil.NativeEndian.PutUint32(0)

	ZeroXor6 = append(binaryutil.NativeEndian.PutUint64(0), binaryutil.NativeEndian.PutUint64(0)...)

	ExprsAllowRelatedEstablished = []expr.Any{
		&expr.Ct{
			Register:       1,
			SourceRegister: false,
			Key:            0,
		},
		// net mask
		&expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            4,
			Mask:           []uint8{0x6, 0x0, 0x0, 0x0},
			Xor:            ZeroXor,
		},
		// net address
		&expr.Cmp{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	ExprsCounterAccept = []expr.Any{
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

func (n *nftablesManager) CleanRoutingRules() {
	n.mux.Lock()
	defer n.mux.Unlock()
	log.Debug("flushing tables")
	n.conn.FlushTable(n.tableIPv6)
	n.conn.FlushTable(n.tableIPv4)
	log.Debugf("flushing tables result in: %v error", n.conn.Flush())
}

// RestoreOrCreateContainers restores existing or creates nftables containers (tables and chains)
func (n *nftablesManager) RestoreOrCreateContainers() error {
	n.mux.Lock()
	defer n.mux.Unlock()

	if n.tableIPv6 != nil && n.tableIPv4 != nil {
		log.Debugf("nftables containers already restored")
		return nil
	}

	tables, err := n.conn.ListTables()
	if err != nil {
		// todo
		return err
	}

	for _, table := range tables {
		if table.Name == NftablesTable {
			if table.Family == nftables.TableFamilyIPv4 {
				n.tableIPv4 = table
				continue
			}
			n.tableIPv6 = table
		}
	}

	if n.tableIPv4 == nil {
		n.tableIPv4 = n.conn.AddTable(&nftables.Table{
			Name:   NftablesTable,
			Family: nftables.TableFamilyIPv4,
		})
	}

	if n.tableIPv6 == nil {
		n.tableIPv6 = n.conn.AddTable(&nftables.Table{
			Name:   NftablesTable,
			Family: nftables.TableFamilyIPv6,
		})
	}

	chains, err := n.conn.ListChains()
	if err != nil {
		// todo
		return err
	}

	n.chains[Ipv4] = make(map[string]*nftables.Chain)
	n.chains[Ipv6] = make(map[string]*nftables.Chain)

	for _, chain := range chains {
		switch {
		case chain.Table.Name == NftablesTable && chain.Table.Family == nftables.TableFamilyIPv4:
			n.chains[Ipv4][chain.Name] = chain
		case chain.Table.Name == NftablesTable && chain.Table.Family == nftables.TableFamilyIPv6:
			n.chains[Ipv6][chain.Name] = chain
		}
	}

	if _, found := n.chains[Ipv4][NftablesRoutingForwardingChain]; !found {
		n.chains[Ipv4][NftablesRoutingForwardingChain] = n.conn.AddChain(&nftables.Chain{
			Name:     NftablesRoutingForwardingChain,
			Table:    n.tableIPv4,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityNATDest + 1,
			Type:     nftables.ChainTypeFilter,
		})
	}

	if _, found := n.chains[Ipv4][NftablesRoutingNatChain]; !found {
		n.chains[Ipv4][NftablesRoutingNatChain] = n.conn.AddChain(&nftables.Chain{
			Name:     NftablesRoutingNatChain,
			Table:    n.tableIPv4,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource - 1,
			Type:     nftables.ChainTypeNAT,
		})
	}

	if _, found := n.chains[Ipv6][NftablesRoutingForwardingChain]; !found {
		n.chains[Ipv6][NftablesRoutingForwardingChain] = n.conn.AddChain(&nftables.Chain{
			Name:     NftablesRoutingForwardingChain,
			Table:    n.tableIPv6,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityNATDest + 1,
			Type:     nftables.ChainTypeFilter,
		})
	}

	if _, found := n.chains[Ipv6][NftablesRoutingNatChain]; !found {
		n.chains[Ipv6][NftablesRoutingNatChain] = n.conn.AddChain(&nftables.Chain{
			Name:     NftablesRoutingNatChain,
			Table:    n.tableIPv6,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource - 1,
			Type:     nftables.ChainTypeNAT,
		})
	}

	err = n.refreshRulesMap()
	if err != nil {
		// todo
		log.Fatal(err)
	}

	n.checkOrCreateDefaultForwardingRules()
	return n.conn.Flush()
}

func (n *nftablesManager) refreshRulesMap() error {
	for _, registeredChains := range n.chains {
		for _, chain := range registeredChains {
			rules, err := n.conn.GetRules(chain.Table, chain)
			if err != nil {
				return err
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

func (n *nftablesManager) checkOrCreateDefaultForwardingRules() {
	_, foundIPv4 := n.rules[Ipv4Forwarding]
	if !foundIPv4 {
		n.rules[Ipv4Forwarding] = n.conn.AddRule(&nftables.Rule{
			Table:    n.tableIPv4,
			Chain:    n.chains[Ipv4][NftablesRoutingForwardingChain],
			Exprs:    ExprsAllowRelatedEstablished,
			UserData: []byte(Ipv4Forwarding),
		})
	}

	_, foundIPv6 := n.rules[Ipv6Forwarding]
	if !foundIPv6 {
		n.rules[Ipv6Forwarding] = n.conn.AddRule(&nftables.Rule{
			Table:    n.tableIPv6,
			Chain:    n.chains[Ipv6][NftablesRoutingForwardingChain],
			Exprs:    ExprsAllowRelatedEstablished,
			UserData: []byte(Ipv6Forwarding),
		})
	}
}

func (n *nftablesManager) InsertRoutingRules(pair RouterPair) error {
	n.mux.Lock()
	defer n.mux.Unlock()

	prefix := netip.MustParsePrefix(pair.source)

	sourceExp := generateCIDRMatcherExpressions("source", pair.source)
	destExp := generateCIDRMatcherExpressions("destination", pair.destination)

	forwardExp := append(sourceExp, append(destExp, ExprsCounterAccept...)...)
	fwdKey := genKey(ForwardingFormat, pair.ID)
	if prefix.Addr().Unmap().Is4() {
		n.rules[fwdKey] = n.conn.InsertRule(&nftables.Rule{
			Table:    n.tableIPv4,
			Chain:    n.chains[Ipv4][NftablesRoutingForwardingChain],
			Exprs:    forwardExp,
			UserData: []byte(fwdKey),
		})
	} else {
		n.rules[fwdKey] = n.conn.InsertRule(&nftables.Rule{
			Table:    n.tableIPv6,
			Chain:    n.chains[Ipv6][NftablesRoutingForwardingChain],
			Exprs:    forwardExp,
			UserData: []byte(fwdKey),
		})
	}

	if pair.masquerade {
		natExp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
		natKey := genKey(NatFormat, pair.ID)

		if prefix.Addr().Unmap().Is4() {
			n.rules[natKey] = n.conn.InsertRule(&nftables.Rule{
				Table:    n.tableIPv4,
				Chain:    n.chains[Ipv4][NftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(natKey),
			})
		} else {
			n.rules[natKey] = n.conn.InsertRule(&nftables.Rule{
				Table:    n.tableIPv6,
				Chain:    n.chains[Ipv6][NftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(natKey),
			})
		}
	}

	return n.conn.Flush()
}

func (n *nftablesManager) RemoveRoutingRules(pair RouterPair) error {
	n.mux.Lock()
	defer n.mux.Unlock()

	err := n.refreshRulesMap()
	if err != nil {
		log.Fatal("issue refreshing rules: %v", err)
	}

	fwdKey := genKey(ForwardingFormat, pair.ID)
	natKey := genKey(NatFormat, pair.ID)
	fwdRule, found := n.rules[fwdKey]
	if found {
		err = n.conn.DelRule(fwdRule)
		if err != nil {
			// todo
			log.Fatal(err)
		}
		delete(n.rules, fwdKey)
	}
	natRule, found := n.rules[natKey]
	if found {
		err = n.conn.DelRule(natRule)
		if err != nil {
			// todo
			log.Fatal(err)
		}
		delete(n.rules, natKey)
	}
	return n.conn.Flush()
}

func getPayloadDirectives(direction string, isIPv4 bool, isIPv6 bool) (uint32, uint32, []byte) {
	switch {
	case direction == ExprDirectionSource && isIPv4:
		return Ipv4SrcOffset, Ipv4Len, ZeroXor
	case direction == ExprDirectionDestination && isIPv4:
		return Ipv4DestOffset, Ipv4Len, ZeroXor
	case direction == ExprDirectionSource && isIPv6:
		return Ipv6SrcOffset, Ipv6Len, ZeroXor6
	case direction == ExprDirectionDestination && isIPv6:
		return Ipv6DestOffset, Ipv6Len, ZeroXor6
	default:
		panic("no matched payload directive")
	}
}

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
