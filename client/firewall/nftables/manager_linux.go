package nftables

import (
	"bytes"
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

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

const (
	// tableNameFilter is the name of the table that is used for filtering by the Netbird client
	tableNameFilter = "netbird-acl"

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

	chainInputFilterIsExists  bool
	chainOutputFilterIsExists bool
	chainForwardIsExists      bool
	chainInputIsExists        bool
	chainOutputIsExists       bool

	rulesetManager *rulesetManager
	setRemovedIPs  map[string]struct{}
	setRemoved     map[string]*nftables.Set

	wgIface iFaceMapper
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
}

// Create nftables firewall manager
func Create(wgIface iFaceMapper) (*Manager, error) {
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
	proto fw.Protocol,
	sPort *fw.Port,
	dPort *fw.Port,
	direction fw.RuleDirection,
	action fw.Action,
	ipsetName string,
	comment string,
) (fw.Rule, error) {
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
	if direction == fw.RuleDirectionOUT {
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
		case fw.ProtocolTCP:
			protoData = []byte{unix.IPPROTO_TCP}
		case fw.ProtocolUDP:
			protoData = []byte{unix.IPPROTO_UDP}
		case fw.ProtocolICMP:
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
		if direction == fw.RuleDirectionOUT {
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

	if action == fw.ActionAccept {
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictAccept})
	} else {
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictDrop})
	}

	userData := []byte(strings.Join([]string{rulesetID, comment}, " "))

	var chain *nftables.Chain
	if direction == fw.RuleDirectionIN {
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

// getRulesetID returns ruleset ID based on given parameters
func (m *Manager) getRulesetID(
	ip net.IP,
	sPort *fw.Port,
	dPort *fw.Port,
	direction fw.RuleDirection,
	action fw.Action,
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

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule fw.Rule) error {
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
		if c.Table.Name != tableNameFilter {
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
		if c.Table.Name != tableNameFilter {
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
		if t.Name == tableNameFilter {
			m.rConn.DelTable(t)
		}
	}

	m.tableFilter = nil

	return m.rConn.Flush()
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

	if err := m.refreshRuleHandles(m.tableFilter, m.chainInputRules); err != nil {
		log.Errorf("failed to refresh rule handles ipv4 input chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.tableFilter, m.chainOutputRules); err != nil {
		log.Errorf("failed to refresh rule handles IPv4 output chain: %v", err)
	}

	return nil
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

func (m *Manager) refreshRuleHandles(table *nftables.Table, chain *nftables.Chain) error {
	if table == nil || chain == nil {
		return nil
	}

	list, err := m.rConn.GetRules(table, chain)
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
	if !m.chainInputFilterIsExists {
		chain, err := m.createChainIfNotExists(chainNameInputRules)
		if err != nil {
			return err
		}
		m.createDefaultExpressions(chain, nftables.ChainHookInput)
		err = m.rConn.Flush()
		if err != nil {
			return err
		}
		m.chainInputRules = chain
		m.chainInputFilterIsExists = true
	}

	if !m.chainOutputFilterIsExists {
		chain, err := m.createChainIfNotExists(chainNameOutputRules)
		if err != nil {
			return err
		}
		m.createDefaultExpressions(chain, nftables.ChainHookOutput)
		err = m.rConn.Flush()
		if err != nil {
			return err
		}
		m.chainOutputRules = chain
		m.chainOutputFilterIsExists = true
	}

	if !m.chainInputIsExists {
		c, err := m.createChainWithHookIfNotExists(chainNameInputFilter, nftables.ChainHookInput)
		if err != nil {
			return err
		}
		m.addJumpRule(c, m.chainInputRules.Name, expr.MetaKeyIIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			return err
		}
		m.chainInputIsExists = true
	}

	if !m.chainOutputIsExists {
		c, err := m.createChainWithHookIfNotExists(chainNameOutputFilter, nftables.ChainHookOutput)
		if err != nil {
			return err
		}
		m.addJumpRule(c, m.chainOutputRules.Name, expr.MetaKeyOIFNAME)
		err = m.rConn.Flush()
		if err != nil {
			return err
		}
		m.chainOutputIsExists = true
	}

	if !m.chainForwardIsExists {
		c, err := m.createChainWithHookIfNotExists(chainNameForwardFilter, nftables.ChainHookForward)
		if err != nil {
			return err
		}

		m.addJumpRule(c, m.chainInputRules.Name, expr.MetaKeyIIFNAME)
		m.addJumpRule(c, m.chainOutputRules.Name, expr.MetaKeyOIFNAME)

		err = m.rConn.Flush()
		if err != nil {
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
		if t.Name == tableNameFilter {
			m.tableFilter = t
			return nil
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: tableNameFilter, Family: nftables.TableFamilyIPv4})
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

func (m *Manager) createDefaultExpressions(chain *nftables.Chain, hookNum nftables.ChainHook) []expr.Any {
	var ifaceKey expr.MetaKey
	var shiftAddress uint32
	if hookNum == nftables.ChainHookInput {
		ifaceKey = expr.MetaKeyIIFNAME
		shiftAddress = 12
	} else {
		ifaceKey = expr.MetaKeyOIFNAME
		shiftAddress = 16 // 12 + 4
	}

	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
	}

	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	expressions = append(expressions,
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
			Op:       expr.CmpOpNeq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.tableFilter,
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
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.tableFilter,
		Chain: chain,
		Exprs: expressions,
	})
	return nil
}

func (m *Manager) addJumpRule(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
	expressions := []expr.Any{
		&expr.Meta{Key: ifaceKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
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

func encodePort(port fw.Port) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(port.Values[0]))
	return bs
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
