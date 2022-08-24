package routemanager

import (
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)
import "github.com/google/nftables"

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

func NewFirewall(parentCTX context.Context) firewallManager {
	ctx, cancel := context.WithCancel(parentCTX)

	if isIptablesSupported() {
		log.Debugf("iptables is supported")
		ipv4, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)

		return &iptablesManager{
			ctx:        ctx,
			stop:       cancel,
			ipv4Client: ipv4,
			ipv6Client: ipv6,
			rules:      make(map[string]map[string][]string),
		}
	}

	log.Debugf("iptables is not supported")

	manager := &nftablesManager{
		ctx:    ctx,
		stop:   cancel,
		conn:   &nftables.Conn{},
		chains: make(map[string]map[string]*nftables.Chain),
		rules:  make(map[string]*nftables.Rule),
	}

	return manager
}

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
	Ipv6                     = "ipv6"
	Ipv4                     = "ipv4"
)

const (
	Ipv6Forwarding   = "netbird-rt-ipv6-forwarding"
	Ipv4Forwarding   = "netbird-rt-ipv4-forwarding"
	Ipv6Nat          = "netbird-rt-ipv6-nat"
	Ipv4Nat          = "netbird-rt-ipv4-nat"
	NatFormat        = "netbird-nat-%s"
	ForwardingFormat = "netbird-fwd-%s"
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

func (n *nftablesManager) cleanupHook() {
	select {
	case <-n.ctx.Done():
		n.mux.Lock()
		defer n.mux.Unlock()
		log.Debug("flushing tables")
		n.conn.FlushTable(n.tableIPv6)
		n.conn.FlushTable(n.tableIPv4)
		log.Debugf("flushing tables result in: %v error", n.conn.Flush())
	}
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
	go n.cleanupHook()

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

func genKey(format string, input string) string {
	return fmt.Sprintf(format, input)
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

const (
	IptablesFilterTable            = "filter"
	IptablesNatTable               = "nat"
	IptablesForwardChain           = "FORWARD"
	IptablesPostRoutingChain       = "POSTROUTING"
	IptablesRoutingNatChain        = "NETBIRD-RT-NAT"
	IptablesRoutingForwardingChain = "NETBIRD-RT-FWD"
	RoutingFinalForwardJump        = "ACCEPT"
	RoutingFinalNatJump            = "MASQUERADE"
)

var IptablesDefaultForwardingRule = []string{"-j", IptablesRoutingForwardingChain, "-m", "comment", "--comment"}
var IptablesDefaultNetbirdForwardingRule = []string{"-j", "RETURN"}
var IptablesDefaultNatRule = []string{"-j", IptablesRoutingNatChain, "-m", "comment", "--comment"}
var IptablesDefaultNetbirdNatRule = []string{"-j", "RETURN"}

type iptablesManager struct {
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	rules      map[string]map[string][]string
	mux        sync.Mutex
}

func (i *iptablesManager) cleanupHook() {
	select {
	case <-i.ctx.Done():
		i.mux.Lock()
		defer i.mux.Unlock()
		log.Debug("flushing tables")
		err := i.ipv4Client.ClearAndDeleteChain(IptablesFilterTable, IptablesRoutingForwardingChain)
		//todo
		if err != nil {
			log.Error(err)
		}
		err = i.ipv4Client.ClearAndDeleteChain(IptablesNatTable, IptablesRoutingNatChain)
		//todo
		if err != nil {
			log.Error(err)
		}
		err = i.ipv6Client.ClearAndDeleteChain(IptablesFilterTable, IptablesRoutingForwardingChain)
		//todo
		if err != nil {
			log.Error(err)
		}
		err = i.ipv6Client.ClearAndDeleteChain(IptablesNatTable, IptablesRoutingNatChain)
		//todo
		if err != nil {
			log.Error(err)
		}

		err = i.cleanJumpRules()
		//todo
		if err != nil {
			log.Error(err)
		}

		log.Info("done cleaning up iptables rules")
	}
}
func (i *iptablesManager) RestoreOrCreateContainers() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	if i.rules[Ipv4][Ipv4Forwarding] != nil && i.rules[Ipv6][Ipv6Forwarding] != nil {
		return nil
	}

	err := createChain(i.ipv4Client, IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv4Client, IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv6Client, IptablesFilterTable, IptablesRoutingForwardingChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}
	err = createChain(i.ipv6Client, IptablesNatTable, IptablesRoutingNatChain)
	//todo
	if err != nil {
		log.Fatal(err)
	}

	// ensure we jump to our chains in the default chains
	err = i.restoreRules(i.ipv4Client)
	//todo
	if err != nil {
		log.Fatal("error while restoring ipv4 rules: ", err)
	}
	err = i.restoreRules(i.ipv6Client)
	//todo
	if err != nil {
		log.Fatal("error while restoring ipv6 rules: ", err)
	}

	for version, _ := range i.rules {
		for key, value := range i.rules[version] {
			log.Debugf("%s rule %s after restore: %#v\n", version, key, value)
		}
	}

	err = i.addJumpRules()
	//todo
	if err != nil {
		log.Fatal("error while creating jump rules: ", err)
	}

	go i.cleanupHook()
	return nil
}

func (i *iptablesManager) addJumpRules() error {
	err := i.cleanJumpRules()
	if err != nil {
		return err
	}
	rule := append(IptablesDefaultForwardingRule, Ipv4Forwarding)
	err = i.ipv4Client.Insert(IptablesFilterTable, IptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultNatRule, Ipv4Nat)
	err = i.ipv4Client.Insert(IptablesNatTable, IptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultForwardingRule, Ipv6Forwarding)
	err = i.ipv6Client.Insert(IptablesFilterTable, IptablesForwardChain, 1, rule...)
	if err != nil {
		return err
	}

	rule = append(IptablesDefaultNatRule, Ipv6Nat)
	err = i.ipv6Client.Insert(IptablesNatTable, IptablesPostRoutingChain, 1, rule...)
	if err != nil {
		return err
	}

	return nil
}

func (i *iptablesManager) cleanJumpRules() error {
	var err error
	rule, found := i.rules[Ipv4][Ipv4Forwarding]
	if found {
		err = i.ipv4Client.DeleteIfExists(IptablesFilterTable, IptablesForwardChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv4][Ipv4Nat]
	if found {
		err = i.ipv4Client.DeleteIfExists(IptablesNatTable, IptablesPostRoutingChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv6][Ipv4Forwarding]
	if found {
		err = i.ipv6Client.DeleteIfExists(IptablesFilterTable, IptablesForwardChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	rule, found = i.rules[Ipv6][Ipv4Nat]
	if found {
		err = i.ipv6Client.DeleteIfExists(IptablesNatTable, IptablesPostRoutingChain, rule...)
		//todo
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *iptablesManager) restoreRules(iptablesClient *iptables.IPTables) error {
	var ipVersion string
	switch iptablesClient.Proto() {
	case iptables.ProtocolIPv4:
		ipVersion = Ipv4
	case iptables.ProtocolIPv6:
		ipVersion = Ipv6
	}

	if i.rules[ipVersion] == nil {
		i.rules[ipVersion] = make(map[string][]string)
	}
	table := IptablesFilterTable
	for _, chain := range []string{IptablesForwardChain, IptablesRoutingForwardingChain} {
		rules, err := iptablesClient.List(table, chain)
		if err != nil {
			return err
		}
		for _, ruleString := range rules {
			rule := strings.Fields(ruleString)
			id := getRuleRouteID(rule)
			if id != "" {
				i.rules[ipVersion][id] = rule[2:]
			}
		}
	}

	table = IptablesNatTable
	for _, chain := range []string{IptablesPostRoutingChain, IptablesRoutingNatChain} {
		rules, err := iptablesClient.List(table, chain)
		if err != nil {
			return err
		}
		for _, ruleString := range rules {
			rule := strings.Fields(ruleString)
			id := getRuleRouteID(rule)
			if id != "" {
				i.rules[ipVersion][id] = rule[2:]
			}
		}
	}

	return nil
}

func createChain(iptables *iptables.IPTables, table, newChain string) error {
	chains, err := iptables.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s %s table chains, error: %v", iptables.Proto(), table, err)
	}
	shouldCreateChain := true
	for _, chain := range chains {
		if chain == newChain {
			shouldCreateChain = false
		}
	}

	if shouldCreateChain {
		err = iptables.NewChain(table, newChain)
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", newChain, iptables.Proto(), table, err)
		}

		if table == IptablesNatTable {
			err = iptables.Append(table, newChain, IptablesDefaultNetbirdNatRule...)
		} else {
			err = iptables.Append(table, newChain, IptablesDefaultNetbirdForwardingRule...)
		}
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s default rule, error: %v", newChain, iptables.Proto(), err)
		}

	}
	return nil
}

func genRuleSpec(jump, id, source, destination string) []string {
	return []string{"-s", source, "-d", destination, "-j", jump, "-m", "comment", "--comment", id}
}

func getRuleRouteID(rule []string) string {
	for i, flag := range rule {
		if flag == "--comment" {
			id := rule[i+1]
			if strings.HasPrefix(id, "netbird-") {
				return id
			}
		}
	}
	return ""
}

func (i *iptablesManager) InsertRoutingRules(pair RouterPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := Ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = Ipv6
	}

	forwardRuleKey := genKey(ForwardingFormat, pair.ID)
	forwardRule := genRuleSpec(RoutingFinalForwardJump, forwardRuleKey, pair.source, pair.destination)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesFilterTable, IptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing forwarding rule, error: %v", err)
		}
		delete(i.rules[ipVersion], forwardRuleKey)
	}
	err = iptablesClient.Insert(IptablesFilterTable, IptablesRoutingForwardingChain, 1, forwardRule...)
	if err != nil {
		return fmt.Errorf("error while adding new forwarding rule, error: %v", err)
	}

	i.rules[ipVersion][forwardRuleKey] = forwardRule

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(NatFormat, pair.ID)
	natRule := genRuleSpec(RoutingFinalNatJump, natRuleKey, pair.source, pair.destination)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesNatTable, IptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing nat rule, error: %v", err)
		}
		delete(i.rules[ipVersion], natRuleKey)
	}
	err = iptablesClient.Insert(IptablesNatTable, IptablesRoutingNatChain, 1, natRule...)
	if err != nil {
		fmt.Errorf("error while adding new nat rule, error: %v", err)
	}

	i.rules[ipVersion][natRuleKey] = natRule

	return nil
}

func (i *iptablesManager) RemoveRoutingRules(pair RouterPair) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	var err error
	prefix := netip.MustParsePrefix(pair.source)
	ipVersion := Ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = Ipv6
	}

	forwardRuleKey := genKey(ForwardingFormat, pair.ID)
	existingRule, found := i.rules[ipVersion][forwardRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesFilterTable, IptablesRoutingForwardingChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing forwarding rule, error: %v", err)
		}
	}
	delete(i.rules[ipVersion], forwardRuleKey)

	if !pair.masquerade {
		return nil
	}

	natRuleKey := genKey(NatFormat, pair.ID)
	existingRule, found = i.rules[ipVersion][natRuleKey]
	if found {
		err = iptablesClient.DeleteIfExists(IptablesNatTable, IptablesRoutingNatChain, existingRule...)
		if err != nil {
			return fmt.Errorf("error while removing existing nat rule, error: %v", err)
		}
	}
	delete(i.rules[ipVersion], natRuleKey)
	return nil
}
