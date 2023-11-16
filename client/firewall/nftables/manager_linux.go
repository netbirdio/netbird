package nftables

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

const (
	// tableName is the name of the table that is used for filtering by the Netbird client
	tableName = "netbird"

	// rules chains contains the effective ACL rules
	chainNameInputRules  = "netbird-acl-input-rules"
	chainNameOutputRules = "netbird-acl-output-rules"

	// filter chains contains the rules that jump to the rules chains
	chainNameInputFilter   = "netbird-acl-input-filter"
	chainNameOutputFilter  = "netbird-acl-output-filter"
	chainNameForwardFilter = "netbird-acl-forward-filter"

	allowNetbirdInputRuleID = "allow Netbird incoming traffic"
)

var anyIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	rConn *nftables.Conn
	sConn *nftables.Conn

	// cached nftalbes objects
	tableFilter      *nftables.Table
	chainInputRules  *nftables.Chain
	chainOutputRules *nftables.Chain

	chainInputRulesIsExists  bool
	chainOutputRulesIsExists bool
	chainForwardIsExists     bool
	chainInputIsExists       bool
	chainOutputIsExists      bool

	rulesetManager *rulesetManager
	setRemovedIPs  map[string]struct{}
	setRemoved     map[string]*nftables.Set

	wgIface iFaceMapper
	router  *router
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
}

// Create nftables firewall manager
func Create(context context.Context, wgIface iFaceMapper) (*Manager, error) {
	// sConn is used for creating sets and adding/removing elements from them
	// it's differ then rConn (which does create new conn for each flush operation)
	// and is permanent. Using same connection for booth type of operations
	// overloads netlink with high amount of rules ( > 10000)
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}

	m := &Manager{
		rConn: &nftables.Conn{},
		sConn: sConn,

		rulesetManager: newRuleManager(),
		setRemovedIPs:  map[string]struct{}{},
		setRemoved:     map[string]*nftables.Set{},

		wgIface: wgIface,

		router: newRouter(context),
	}

	if err := m.Reset(); err != nil {
		return nil, err
	}

	return m, nil
}

// AddFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *Manager) AddFiltering(
	ip net.IP,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
	comment string,
) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	err := m.createFilterTableIfNotExists()
	if err != nil {
		return nil, err
	}

	err = m.createDefaultChains()
	if err != nil {
		return nil, err
	}

	var ipset *nftables.Set
	rawIP := ip.To4()
	rulesetID := m.getRulesetID(ip, sPort, dPort, direction, action, ipsetName)
	if ipsetName != "" {
		// if we already have set with given name, just add ip to the set
		// and return rule with new ID in other case let's create rule
		// with fresh created set and set element

		var isSetNew bool
		ipset, err = m.rConn.GetSetByName(m.tableFilter, ipsetName)
		if err != nil {
			if ipset, err = m.createSet(m.tableFilter, rawIP, ipsetName); err != nil {
				return nil, fmt.Errorf("get set name: %v", err)
			}
			isSetNew = true
		}

		if err := m.sConn.SetAddElements(ipset, []nftables.SetElement{{Key: rawIP}}); err != nil {
			return nil, fmt.Errorf("add set element for the first time: %v", err)
		}
		if err := m.sConn.Flush(); err != nil {
			return nil, fmt.Errorf("flush add elements: %v", err)
		}

		if !isSetNew {
			// if we already have nftables rules with set for given direction
			// just add new rule to the ruleset and return new fw.Rule object

			if ruleset, ok := m.rulesetManager.getRuleset(rulesetID); ok {
				return m.rulesetManager.addRule(ruleset, rawIP)
			}
			// if ipset exists but it is not linked to rule for given direction
			// create new rule for direction and bind ipset to it later
		}
	}

	ifaceKey := expr.MetaKeyIIFNAME
	if direction == firewall.RuleDirectionOUT {
		ifaceKey = expr.MetaKeyOIFNAME
	}
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
	}

	if proto != "all" {
		expressions = append(expressions, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       uint32(9),
			Len:          uint32(1),
		})

		var protoData []byte
		switch proto {
		case firewall.ProtocolTCP:
			protoData = []byte{unix.IPPROTO_TCP}
		case firewall.ProtocolUDP:
			protoData = []byte{unix.IPPROTO_UDP}
		case firewall.ProtocolICMP:
			protoData = []byte{unix.IPPROTO_ICMP}
		default:
			return nil, fmt.Errorf("unsupported protocol: %s", proto)
		}
		expressions = append(expressions, &expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     protoData,
		})
	}

	// check if rawIP contains zeroed IPv4 0.0.0.0 or same IPv6 value
	// in that case not add IP match expression into the rule definition
	if !bytes.HasPrefix(anyIP, rawIP) {
		// source address position
		addrLen := uint32(len(rawIP))
		addrOffset := uint32(12)
		if addrLen == 16 {
			addrOffset = 8
		}

		// change to destination address position if need
		if direction == firewall.RuleDirectionOUT {
			addrOffset += addrLen
		}

		expressions = append(expressions,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       addrOffset,
				Len:          addrLen,
			},
		)
		// add individual IP for match if no ipset defined
		if ipset == nil {
			expressions = append(expressions,
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     rawIP,
				},
			)
		} else {
			expressions = append(expressions,
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        ipsetName,
					SetID:          ipset.ID,
				},
			)
		}
	}

	if sPort != nil && len(sPort.Values) != 0 {
		expressions = append(expressions,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     encodePort(*sPort),
			},
		)
	}

	if dPort != nil && len(dPort.Values) != 0 {
		expressions = append(expressions,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     encodePort(*dPort),
			},
		)
	}

	if action == firewall.ActionAccept {
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictAccept})
	} else {
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictDrop})
	}

	userData := []byte(strings.Join([]string{rulesetID, comment}, " "))

	var chain *nftables.Chain
	if direction == firewall.RuleDirectionIN {
		chain = m.chainInputRules
	} else {
		chain = m.chainOutputRules
	}
	rule := m.rConn.InsertRule(&nftables.Rule{
		Table:    m.tableFilter,
		Chain:    chain,
		Position: 0,
		Exprs:    expressions,
		UserData: userData,
	})
	if err := m.rConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush insert rule: %v", err)
	}

	ruleset := m.rulesetManager.createRuleset(rulesetID, rule, ipset)
	return m.rulesetManager.addRule(ruleset, rawIP)
}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	nativeRule, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	if nativeRule.nftRule == nil {
		return nil
	}

	if nativeRule.nftSet != nil {
		// call twice of delete set element raises error
		// so we need to check if element is already removed
		key := fmt.Sprintf("%s:%v", nativeRule.nftSet.Name, nativeRule.ip)
		if _, ok := m.setRemovedIPs[key]; !ok {
			err := m.sConn.SetDeleteElements(nativeRule.nftSet, []nftables.SetElement{{Key: nativeRule.ip}})
			if err != nil {
				log.Errorf("delete elements for set %q: %v", nativeRule.nftSet.Name, err)
			}
			if err := m.sConn.Flush(); err != nil {
				return err
			}
			m.setRemovedIPs[key] = struct{}{}
		}
	}

	if m.rulesetManager.deleteRule(nativeRule) {
		// deleteRule indicates that we still have IP in the ruleset
		// it means we should not remove the nftables rule but need to update set
		// so we prepare IP to be removed from set on the next flush call
		return nil
	}

	// ruleset doesn't contain IP anymore (or contains only one), remove nft rule
	if err := m.rConn.DelRule(nativeRule.nftRule); err != nil {
		log.Errorf("failed to delete rule: %v", err)
	}
	if err := m.rConn.Flush(); err != nil {
		return err
	}
	nativeRule.nftRule = nil

	if nativeRule.nftSet != nil {
		if _, ok := m.setRemoved[nativeRule.nftSet.Name]; !ok {
			m.setRemoved[nativeRule.nftSet.Name] = nativeRule.nftSet
		}
		nativeRule.nftSet = nil
	}

	return nil
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) InsertRoutingRules(pair firewall.RouterPair) error {
	return m.router.InsertRoutingRules(pair)
}

func (m *Manager) RemoveRoutingRules(pair firewall.RouterPair) error {
	return m.router.RemoveRoutingRules(pair)
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.rConn.ListChains()
	if err != nil {
		return fmt.Errorf("list of chains: %w", err)
	}

	// remove filter chains
	for _, c := range chains {
		if c.Table.Name != tableName {
			continue
		}

		if c.Name == chainNameForwardFilter {
			m.rConn.DelChain(c)
			continue
		}

		if c.Name == chainNameInputFilter {
			m.rConn.DelChain(c)
		}

		if c.Name == chainNameOutputFilter {
			m.rConn.DelChain(c)
		}
	}

	for _, c := range chains {
		// delete Netbird allow input traffic rule if it exists
		if c.Table.Name == "filter" && c.Name == "INPUT" {
			rules, err := m.rConn.GetRules(c.Table, c)
			if err != nil {
				log.Errorf("get rules for chain %q: %v", c.Name, err)
				continue
			}
			for _, r := range rules {
				if bytes.Equal(r.UserData, []byte(allowNetbirdInputRuleID)) {
					if err := m.rConn.DelRule(r); err != nil {
						log.Errorf("delete rule: %v", err)
					}
				}
			}
		}

		// remove rules chains
		if c.Table.Name != tableName {
			continue
		}

		if c.Name == chainNameInputRules || c.Name == chainNameOutputRules {
			m.rConn.DelChain(c)
		}
	}

	tables, err := m.rConn.ListTables()
	if err != nil {
		return fmt.Errorf("list of tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}

	m.tableFilter = nil

	return m.rConn.Flush()
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.rConn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("list of chains: %w", err)
	}

	var chain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == "filter" && c.Name == "INPUT" {
			chain = c
			break
		}
	}

	if chain == nil {
		log.Debugf("chain INPUT not found. Skipping add allow netbird rule")
		return nil
	}

	rules, err := m.rConn.GetRules(chain.Table, chain)
	if err != nil {
		return fmt.Errorf("failed to get rules for the INPUT chain: %v", err)
	}

	if rule := m.detectAllowNetbirdRule(rules); rule != nil {
		log.Debugf("allow netbird rule already exists: %v", rule)
		return nil
	}

	m.applyAllowNetbirdRules(chain)

	err = m.rConn.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush allow input netbird rules: %v", err)
	}
	return nil
}

// getRulesetID returns ruleset ID based on given parameters
func (m *Manager) getRulesetID(
	ip net.IP,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
) string {
	rulesetID := ":" + strconv.Itoa(int(direction)) + ":"
	if sPort != nil {
		rulesetID += sPort.String()
	}
	rulesetID += ":"
	if dPort != nil {
		rulesetID += dPort.String()
	}
	rulesetID += ":"
	rulesetID += strconv.Itoa(int(action))
	if ipsetName == "" {
		return "ip:" + ip.String() + rulesetID
	}
	return "set:" + ipsetName + rulesetID
}

// createSet in given table by name
func (m *Manager) createSet(table *nftables.Table, rawIP []byte, name string) (*nftables.Set, error) {
	keyType := nftables.TypeIPAddr
	if len(rawIP) == 16 {
		keyType = nftables.TypeIP6Addr
	}
	// else we create new ipset and continue creating rule
	ipset := &nftables.Set{
		Name:    name,
		Table:   table,
		Dynamic: true,
		KeyType: keyType,
	}

	if err := m.rConn.AddSet(ipset, nil); err != nil {
		return nil, fmt.Errorf("create set: %v", err)
	}

	if err := m.rConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush created set: %v", err)
	}

	return ipset, nil
}

// Flush rule/chain/set operations from the buffer
//
// Method also get all rules after flush and refreshes handle values in the rulesets
func (m *Manager) Flush() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.flushWithBackoff(); err != nil {
		return err
	}

	// set must be removed after flush rule changes
	// otherwise we will get error
	for _, s := range m.setRemoved {
		m.rConn.FlushSet(s)
		m.rConn.DelSet(s)
	}

	if len(m.setRemoved) > 0 {
		if err := m.flushWithBackoff(); err != nil {
			return err
		}
	}

	m.setRemovedIPs = map[string]struct{}{}
	m.setRemoved = map[string]*nftables.Set{}

	if err := m.refreshRuleHandles(m.chainInputRules); err != nil {
		log.Errorf("failed to refresh rule handles ipv4 input chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.chainOutputRules); err != nil {
		log.Errorf("failed to refresh rule handles IPv4 output chain: %v", err)
	}

	return nil
}

func (m *Manager) flushWithBackoff() (err error) {
	backoff := 4
	backoffTime := 1000 * time.Millisecond
	for i := 0; ; i++ {
		err = m.rConn.Flush()
		if err != nil {
			if !strings.Contains(err.Error(), "busy") {
				return
			}
			log.Error("failed to flush nftables, retrying...")
			if i == backoff-1 {
				return err
			}
			time.Sleep(backoffTime)
			backoffTime *= 2
			continue
		}
		break
	}
	return
}

func (m *Manager) refreshRuleHandles(chain *nftables.Chain) error {
	if m.tableFilter == nil || chain == nil {
		return nil
	}

	list, err := m.rConn.GetRules(m.tableFilter, chain)
	if err != nil {
		return err
	}

	for _, rule := range list {
		if len(rule.UserData) != 0 {
			if err := m.rulesetManager.setNftRuleHandle(rule); err != nil {
				log.Errorf("failed to set rule handle: %v", err)
			}
		}
	}

	return nil
}

func (m *Manager) applyAllowNetbirdRules(chain *nftables.Chain) {
	rule := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(m.wgIface.Name()),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
		UserData: []byte(allowNetbirdInputRuleID),
	}
	_ = m.rConn.InsertRule(rule)
}

func (m *Manager) detectAllowNetbirdRule(existedRules []*nftables.Rule) *nftables.Rule {
	ifName := ifname(m.wgIface.Name())
	for _, rule := range existedRules {
		if rule.Table.Name == "filter" && rule.Chain.Name == "INPUT" {
			if len(rule.Exprs) < 4 {
				if e, ok := rule.Exprs[0].(*expr.Meta); !ok || e.Key != expr.MetaKeyIIFNAME {
					continue
				}
				if e, ok := rule.Exprs[1].(*expr.Cmp); !ok || e.Op != expr.CmpOpEq || !bytes.Equal(e.Data, ifName) {
					continue
				}
				return rule
			}
		}
	}
	return nil
}

func (m *Manager) createDefaultChains() (err error) {
	if !m.chainInputRulesIsExists {
		chain, err := m.createChainIfNotExists(chainNameInputRules)
		if err != nil {
			return err
		}
		m.createDefaultExpressions(chain, expr.MetaKeyIIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			log.Errorf("failed to create chain (%s): %s", chainNameInputRules, err)
			return err
		}
		m.chainInputRules = chain
		m.chainInputRulesIsExists = true
	}

	if !m.chainOutputRulesIsExists {
		chain, err := m.createChainIfNotExists(chainNameOutputRules)
		if err != nil {
			return err
		}
		m.createDefaultExpressions(chain, expr.MetaKeyOIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			log.Errorf("failed to create chain (%s): %s", chainNameOutputRules, err)
			return err
		}
		m.chainOutputRules = chain
		m.chainOutputRulesIsExists = true
	}

	if !m.chainInputIsExists {
		// type filter hook input priority filter; policy accept;
		c, err := m.createChainWithHookIfNotExists(chainNameInputFilter, nftables.ChainHookInput)
		if err != nil {
			return err
		}
		// iifname "wt0" ip saddr [netbird-range]/16 ip daddr [netbird-range]/16 jump netbird-acl-input-rules
		m.addJumpRule(c, m.chainInputRules.Name, expr.MetaKeyIIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			log.Errorf("failed to create chain (%s): %s", chainNameInputFilter, err)
			return err
		}
		m.chainInputIsExists = true
	}

	if !m.chainOutputIsExists {
		// type filter hook output priority filter; policy accept;
		c, err := m.createChainWithHookIfNotExists(chainNameOutputFilter, nftables.ChainHookOutput)
		if err != nil {
			return err
		}
		// oifname "wt0" ip saddr 100.72.0.0/16 ip daddr 100.72.0.0/16 jump netbird-acl-output-rules
		m.addJumpRule(c, m.chainOutputRules.Name, expr.MetaKeyOIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			log.Errorf("failed to create chain (%s): %s", chainNameOutputFilter, err)
			return err
		}
		m.chainOutputIsExists = true
	}

	if !m.chainForwardIsExists {
		c, err := m.createChainWithHookIfNotExists(chainNameForwardFilter, nftables.ChainHookForward)
		if err != nil {
			return err
		}

		// oifname "wt0" ip saddr [netbird-range]/16 jump netbird-acl-output-rules
		// iifname "wt0" ip daddr [netbird-range]/16 jump netbird-acl-input-rules
		m.addJumpRuleWithIPRestriction(c, m.chainOutputRules.Name, expr.MetaKeyOIFNAME)
		m.addJumpRuleWithIPRestriction(c, m.chainInputRules.Name, expr.MetaKeyIIFNAME)

		err = m.rConn.Flush()
		if err != nil {
			log.Errorf("failed to create chain (%s): %s", chainNameForwardFilter, err)
			return err
		}
		m.chainForwardIsExists = true
	}

	return nil
}

func (m *Manager) createFilterTableIfNotExists() error {
	if m.tableFilter != nil {
		return nil
	}

	tables, err := m.rConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("list of tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == tableName {
			m.tableFilter = t
			return nil
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4})
	err = m.rConn.Flush()
	m.tableFilter = table
	return err
}

func (m *Manager) createChainIfNotExists(name string) (*nftables.Chain, error) {
	chains, err := m.rConn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("list of chains: %w", err)
	}

	for _, c := range chains {
		if c.Name == name && c.Table.Name == m.tableFilter.Name {
			return c, nil
		}
	}
	chain := &nftables.Chain{
		Name:  name,
		Table: m.tableFilter,
	}

	chain = m.rConn.AddChain(chain)
	return chain, nil
}

func (m *Manager) createChainWithHookIfNotExists(name string, hookNum nftables.ChainHook) (*nftables.Chain, error) {
	chains, err := m.rConn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("list of chains: %w", err)
	}

	for _, c := range chains {
		if c.Name == name && c.Table.Name == m.tableFilter.Name {
			return c, nil
		}
	}

	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     name,
		Table:    m.tableFilter,
		Hooknum:  hookNum,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	chain = m.rConn.AddChain(chain)
	return chain, nil
}

func (m *Manager) createDefaultExpressions(chain *nftables.Chain, ifaceKey expr.MetaKey) []expr.Any {
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.tableFilter,
		Chain: chain,
		Exprs: expressions,
	})
	return nil
}

// addJumpRuleWithIPRestriction adds jump rule with IP restriction, The restriction required for to ignore the ACL
// rules on routed traffic.
func (m *Manager) addJumpRuleWithIPRestriction(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            4,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			Mask:           m.wgIface.Address().Network.Mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: to,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})

	expressions = []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            4,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			Mask:           m.wgIface.Address().Network.Mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: to,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})
}

func (m *Manager) addJumpRuleWithIPRestriction2(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
	var shiftAddress uint32
	if ifaceKey != expr.MetaKeyOIFNAME {
		shiftAddress = 12
	} else {
		shiftAddress = 16 // 12 + 4
	}

	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       shiftAddress,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            4,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			Mask:           m.wgIface.Address().Network.Mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: to,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})
}

func (m *Manager) addJumpRule(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            4,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			Mask:           m.wgIface.Address().Network.Mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            4,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			Mask:           m.wgIface.Address().Network.Mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: to,
		},
	}
	_ = m.rConn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})
}

func encodePort(port firewall.Port) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(port.Values[0]))
	return bs
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
