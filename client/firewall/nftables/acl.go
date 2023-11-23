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

var (
	anyIP           = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	postroutingMark = []byte{0xe4, 0x7, 0x0, 0x00}
)

type AclManager struct {
	rConn               *nftables.Conn
	sConn               *nftables.Conn
	wgIface             iFaceMapper
	routeingFwChainName string

	workTable        *nftables.Table
	chainInputRules  *nftables.Chain
	chainOutputRules *nftables.Chain
	chainFwFilter    *nftables.Chain
	chainPrerouting  *nftables.Chain

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
) ([]firewall.Rule, error) {
	var ipset *nftables.Set
	var isNewSet bool
	rawIP := ip.To4()
	if rawIP == nil {
		return nil, fmt.Errorf("unsupported IP version: %s", ip.String())
	}

	if ipsetName != "" {
		var err error
		ipset, isNewSet, err = m.addIpToSet(ipsetName, rawIP)
		if err != nil {
			return nil, err
		}
	}

	ioRule, err := m.addIOFiltering(ip, proto, sPort, dPort, direction, action, ipset, isNewSet, comment)
	if err != nil {
		return nil, err
	}

	if !shouldAddToPrerouting(isNewSet, proto, direction) {
		return []firewall.Rule{ioRule}, nil
	}

	preroutingRule, err := m.addPreroutingFiltering(ipset, proto, sPort, dPort, rawIP)
	if err != nil {
		return []firewall.Rule{ioRule}, err
	}

	return []firewall.Rule{ioRule, preroutingRule}, nil
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

	if err := m.refreshRuleHandles(m.chainPrerouting); err != nil {
		log.Errorf("failed to refresh rule handles IPv4 prerouting chain: %v", err)
	}

	return nil
}

func (m *AclManager) addIOFiltering(ip net.IP, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action, ipset *nftables.Set, isNewSet bool, comment string) (*Rule, error) {
	rawIP := ip.To4()

	rulesetID := m.getRulesetID(ip, sPort, dPort, direction, action, ipset)
	if ipset != nil && !isNewSet {
		// if we already have nftables rules with set for given direction
		// just add new rule to the ruleset and return new fw.Rule object

		if m.rulesetManager.isRulesetExists(rulesetID) {
			return m.rulesetManager.addRule(rulesetID, rawIP)
		}
		// if ipset exists but it is not linked to rule for given direction
		// create new rule for direction and bind ipset to it later
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

	if proto != firewall.ProtocolALL {
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
					SetName:        ipset.Name,
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

	switch action {
	case firewall.ActionAccept:
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictAccept})
	case firewall.ActionDrop:
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
	m.rulesetManager.createRuleset(rulesetID, rule, ipset)
	return m.rulesetManager.addRule(rulesetID, rawIP)
}

func (m *AclManager) addPreroutingFiltering(ipset *nftables.Set, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, rawIP []byte) (*Rule, error) {
	var port *firewall.Port
	var protoData []byte
	switch proto {
	case firewall.ProtocolTCP:
		protoData = []byte{unix.IPPROTO_TCP}
		if sPort != nil {
			port = sPort
		} else {
			port = dPort
		}
	case firewall.ProtocolUDP:
		protoData = []byte{unix.IPPROTO_UDP}
		if sPort != nil {
			port = sPort
		} else {
			port = dPort
		}
	case firewall.ProtocolICMP:
		protoData = []byte{unix.IPPROTO_ICMP}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}

	var ipExpression expr.Any
	// add individual IP for match if no ipset defined
	if ipset == nil {
		ipExpression = &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     rawIP,
		}
	} else {
		ipExpression = &expr.Lookup{
			SourceRegister: 1,
			SetName:        ipset.Name,
			SetID:          ipset.ID,
		}
	}

	expressions := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		ipExpression,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     m.wgIface.Address().IP.To4(),
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       uint32(9),
			Len:          uint32(1),
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     protoData,
		},
	}

	if port != nil {
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
				Data:     encodePort(*port),
			},
		)
	}

	expressions = append(expressions,
		&expr.Immediate{
			Register: 1,
			Data:     postroutingMark,
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	)

	rulesetID := fmt.Sprintf("set:%s:%s:%v", ipset.Name, proto, port)
	rule := m.rConn.InsertRule(&nftables.Rule{
		Table:    m.workTable,
		Chain:    m.chainPrerouting,
		Position: 0,
		Exprs:    expressions,
		UserData: []byte(rulesetID),
	})

	if err := m.rConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush insert rule: %v", err)
	}

	m.rulesetManager.createRuleset(rulesetID, rule, ipset)
	return m.rulesetManager.addRule(rulesetID, rawIP)
}

func (m *AclManager) createDefaultChains() (err error) {
	// chainNameInputRules
	chain := m.createChain(chainNameInputRules)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}
	m.chainInputRules = chain

	// chainNameOutputRules
	chain = m.createChain(chainNameOutputRules)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameOutputRules, err)
		return err
	}
	m.chainOutputRules = chain

	// netbird-acl-input-filter
	// type filter hook input priority filter; policy accept;
	chain = m.createFilterChainWithHook(chainNameInputFilter, nftables.ChainHookInput)
	m.addFwdAllow(chain, expr.MetaKeyIIFNAME)
	m.addJumpRule(chain, m.chainInputRules.Name, expr.MetaKeyIIFNAME) // to netbird-acl-input-rules
	m.addDropExpressions(chain, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}

	// netbird-acl-output-filter
	// type filter hook output priority filter; policy accept;
	chain = m.createFilterChainWithHook(chainNameOutputFilter, nftables.ChainHookOutput)
	m.addFwdAllow(chain, expr.MetaKeyOIFNAME)
	m.addJumpRule(chain, m.chainOutputRules.Name, expr.MetaKeyOIFNAME) // to netbird-acl-output-rules
	m.addDropExpressions(chain, expr.MetaKeyOIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameOutputFilter, err)
		return err
	}

	// netbird-acl-forward-filter
	m.chainFwFilter = m.createFilterChainWithHook(chainNameForwardFilter, nftables.ChainHookForward)
	m.addJumpRulesToRtForward() // to
	m.addMarkAccept()
	m.addJumpRuleToInputChain() // to netbird-acl-input-rules
	m.addDropExpressions(m.chainFwFilter, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", chainNameForwardFilter, err)
		return err
	}

	// netbird-acl-output-filter
	// type filter hook output priority filter; policy accept;
	m.chainPrerouting = m.createPreroutingMangle()
	err = m.rConn.Flush()
	if err != nil {
		log.Errorf("failed to create chain (%s): %s", m.chainPrerouting.Name, err)
		return err
	}
	return nil
}

func (m *AclManager) addJumpRulesToRtForward() {
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

func (m *AclManager) addMarkAccept() {
	// oifname "wt0" meta mark 0x000007e4 accept
	// iifname "wt0" meta mark 0x000007e4 accept
	ifaces := []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME}
	for _, iface := range ifaces {
		expressions := []expr.Any{
			&expr.Meta{Key: iface, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(m.wgIface.Name()),
			},
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     postroutingMark,
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		}

		_ = m.rConn.AddRule(&nftables.Rule{
			Table: m.workTable,
			Chain: m.chainFwFilter,
			Exprs: expressions,
		})
	}
}

func (m *AclManager) createChain(name string) *nftables.Chain {
	chain := &nftables.Chain{
		Name:  name,
		Table: m.workTable,
	}

	chain = m.rConn.AddChain(chain)
	return chain
}

func (m *AclManager) createFilterChainWithHook(name string, hookNum nftables.ChainHook) *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     name,
		Table:    m.workTable,
		Hooknum:  hookNum,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	return m.rConn.AddChain(chain)
}

func (m *AclManager) createPreroutingMangle() *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     "netbird-acl-prerouting-filter",
		Table:    m.workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	chain = m.rConn.AddChain(chain)

	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
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
			Op:       expr.CmpOpNeq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
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
			Data:     m.wgIface.Address().IP.To4(),
		},
		&expr.Immediate{
			Register: 1,
			Data:     postroutingMark,
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: chain,
		Exprs: expressions,
	})
	chain = m.rConn.AddChain(chain)
	return chain
}

func (m *AclManager) addDropExpressions(chain *nftables.Chain, ifaceKey expr.MetaKey) []expr.Any {
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

func (m *AclManager) addJumpRuleToInputChain() {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: m.chainInputRules.Name,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: m.chainFwFilter,
		Exprs: expressions,
	})
}

func (m *AclManager) addFwdAllow(chain *nftables.Chain, iifname expr.MetaKey) {
	ip, _ := netip.AddrFromSlice(m.wgIface.Address().Network.IP.To4())
	var srcOp, dstOp expr.CmpOp
	if iifname == expr.MetaKeyIIFNAME {
		srcOp = expr.CmpOpNeq
		dstOp = expr.CmpOpEq
	} else {
		srcOp = expr.CmpOpEq
		dstOp = expr.CmpOpNeq
	}
	expressions := []expr.Any{
		&expr.Meta{Key: iifname, Register: 1},
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
			Op:       srcOp,
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
			Op:       dstOp,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
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

func (m *AclManager) addIpToSet(ipsetName string, rawIP []byte) (*nftables.Set, bool, error) {
	// if we already have set with given name, just add ip to the set
	// and return rule with new ID in other case let's create rule
	// with fresh created set and set element
	var isSetNew bool
	ipset, err := m.rConn.GetSetByName(m.workTable, ipsetName)
	if err != nil {
		if ipset, err = m.createSet(m.workTable, rawIP, ipsetName); err != nil {
			return nil, false, fmt.Errorf("get set name: %v", err)
		}
		isSetNew = true
	}

	if err := m.sConn.SetAddElements(ipset, []nftables.SetElement{{Key: rawIP}}); err != nil {
		return nil, isSetNew, fmt.Errorf("add set element for the first time: %v", err)
	}
	if err := m.sConn.Flush(); err != nil {
		return nil, isSetNew, fmt.Errorf("flush add elements: %v", err)
	}

	return ipset, isSetNew, nil
}

// getRulesetID returns ruleset ID based on given parameters
func (m *AclManager) getRulesetID(
	ip net.IP,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipset *nftables.Set,
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
	if ipset == nil {
		return "ip:" + ip.String() + rulesetID
	}
	return "set:" + ipset.Name + rulesetID
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

func shouldAddToPrerouting(isNewSet bool, proto firewall.Protocol, direction firewall.RuleDirection) bool {
	if !isNewSet {
		return false
	}
	if proto == "all" {
		return false
	}

	if direction != firewall.RuleDirectionIN {
		return false
	}
	return true
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
