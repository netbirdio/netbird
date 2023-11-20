package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

const (

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

type AclManager struct {
	rConn               *nftables.Conn
	sConn               *nftables.Conn
	wgIface             iFaceMapper
	routeingFwChainName string

	workTable        *nftables.Table
	chainInputRules  *nftables.Chain
	chainOutputRules *nftables.Chain
	chainFwFilter    *nftables.Chain

	rulesetManager *rulesetManager
	setRemovedIPs  map[string]struct{}
	setRemoved     map[string]*nftables.Set
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
}

func newAclManager(table *nftables.Table, wgIface iFaceMapper, routeingFwChainName string) (*AclManager, error) {
	// sConn is used for creating sets and adding/removing elements from them
	// it's differ then rConn (which does create new conn for each flush operation)
	// and is permanent. Using same connection for booth type of operations
	// overloads netlink with high amount of rules ( > 10000)
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}

	m := &AclManager{
		rConn:               &nftables.Conn{},
		sConn:               sConn,
		wgIface:             wgIface,
		workTable:           table,
		routeingFwChainName: routeingFwChainName,

		rulesetManager: newRuleManager(),
		setRemovedIPs:  map[string]struct{}{},
		setRemoved:     map[string]*nftables.Set{},
	}

	if err := m.createDefaultChains(); err != nil {
		return nil, err
	}

	return m, nil
}

// AddFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *AclManager) AddFiltering(
	ip net.IP,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
	comment string,
) (firewall.Rule, error) {
	var ipset *nftables.Set
	var err error
	rawIP := ip.To4()
	rulesetID := m.getRulesetID(ip, sPort, dPort, direction, action, ipsetName)
	if ipsetName != "" {
		// if we already have set with given name, just add ip to the set
		// and return rule with new ID in other case let's create rule
		// with fresh created set and set element

		var isSetNew bool
		ipset, err = m.rConn.GetSetByName(m.workTable, ipsetName)
		if err != nil {
			if ipset, err = m.createSet(m.workTable, rawIP, ipsetName); err != nil {
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

	// check if rawIP contains zeroed IPv4 0.0.0.0 value
	// in that case not add IP match expression into the rule definition
	if !bytes.HasPrefix(anyIP, rawIP) {
		// source address position
		addrOffset := uint32(12)
		if direction == firewall.RuleDirectionOUT {
			addrOffset += 4 // is ipv4 address length
		}

		expressions = append(expressions,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       addrOffset,
				Len:          4,
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
		Table:    m.workTable,
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
func (m *AclManager) DeleteRule(rule firewall.Rule) error {
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

// getRulesetID returns ruleset ID based on given parameters
func (m *AclManager) getRulesetID(
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
func (m *AclManager) createSet(table *nftables.Table, rawIP []byte, name string) (*nftables.Set, error) {
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
func (m *AclManager) Flush() error {
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

func (m *AclManager) flushWithBackoff() (err error) {
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
			backoffTime = backoffTime * 2
			continue
		}
		break
	}
	return
}

func (m *AclManager) refreshRuleHandles(chain *nftables.Chain) error {
	if m.workTable == nil || chain == nil {
		return nil
	}

	list, err := m.rConn.GetRules(m.workTable, chain)
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

func (m *AclManager) createDefaultChains() (err error) {
	// chainNameInputRules
	chain := m.createChain(chainNameInputRules)
	m.createDefaultExpressions(chain, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameInputRules, err)
		return err
	}
	m.chainInputRules = chain

	// chainNameOutputRules
	chain = m.createChain(chainNameOutputRules)
	m.createDefaultExpressions(chain, expr.MetaKeyOIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameOutputRules, err)
		return err
	}
	m.chainOutputRules = chain

	// netbird-acl-input-filter
	// type filter hook input priority filter; policy accept;
	c := m.createChainWithHook(chainNameInputFilter, nftables.ChainHookInput)
	// iifname "wt0" ip saddr [netbird-range]/16 ip daddr [netbird-range]/16 jump netbird-acl-input-rules
	m.addJumpRule(c, m.chainInputRules.Name, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameInputFilter, err)
		return err
	}

	// netbird-acl-output-filter
	// type filter hook output priority filter; policy accept;
	c = m.createChainWithHook(chainNameOutputFilter, nftables.ChainHookOutput)
	// oifname "wt0" ip saddr 100.72.0.0/16 ip daddr 100.72.0.0/16 jump netbird-acl-output-rules
	m.addJumpRule(c, m.chainOutputRules.Name, expr.MetaKeyOIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameOutputFilter, err)
		return err
	}

	// netbird-acl-forward-filter
	m.chainFwFilter = m.createChainWithHook(chainNameForwardFilter, nftables.ChainHookForward)
	m.addJumpToRouteForward()
	// iifname "wt0" jump netbird-acl-input-rules
	// oifname "wt0" jump netbird-acl-output-rules
	m.addJumpRulesToACLrules(m.chainInputRules.Name, expr.MetaKeyIIFNAME)
	m.addJumpRulesToACLrules(m.chainOutputRules.Name, expr.MetaKeyOIFNAME)

	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameForwardFilter, err)
		return err
	}

	return nil
}

func (m *AclManager) addJumpToRouteForward() {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: m.routeingFwChainName,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: m.chainFwFilter,
		Exprs: expressions,
	})

	expressions = []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: m.routeingFwChainName,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: m.chainFwFilter,
		Exprs: expressions,
	})
}

func (m *AclManager) createChain(name string) *nftables.Chain {
	chain := &nftables.Chain{
		Name:  name,
		Table: m.workTable,
	}

	chain = m.rConn.AddChain(chain)
	return chain
}

func (m *AclManager) createChainWithHook(name string, hookNum nftables.ChainHook) *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     name,
		Table:    m.workTable,
		Hooknum:  hookNum,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	chain = m.rConn.AddChain(chain)
	return chain
}

func (m *AclManager) createDefaultExpressions(chain *nftables.Chain, ifaceKey expr.MetaKey) []expr.Any {
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
		Table: m.workTable,
		Chain: chain,
		Exprs: expressions,
	})
	return nil
}

func (m *AclManager) addJumpRulesToACLrules(to string, ifaceKey expr.MetaKey) {
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
		Table: m.workTable,
		Chain: m.chainFwFilter,
		Exprs: expressions,
	})
}

func (m *AclManager) addJumpRuleWithIPRestriction2(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
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

func (m *AclManager) addJumpRule(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
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
