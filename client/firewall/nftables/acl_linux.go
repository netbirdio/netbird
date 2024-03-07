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
	anyIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	nullAddress4    = []byte{0x0, 0x0, 0x0, 0x0}
	nullAddress6    = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	postroutingMark = []byte{0xe4, 0x7, 0x0, 0x00}
)

type AclManager struct {
	rConn               *nftables.Conn
	sConn               *nftables.Conn
	wgIface             iFaceMapper
	routeingFwChainName string

	workTable         *nftables.Table
	workTable6        *nftables.Table
	v6Active          bool
	chainInputRules   *nftables.Chain
	chainOutputRules  *nftables.Chain
	chainFwFilter     *nftables.Chain
	chainPrerouting   *nftables.Chain
	chainInputRules6  *nftables.Chain
	chainOutputRules6 *nftables.Chain
	chainFwFilter6    *nftables.Chain
	chainPrerouting6  *nftables.Chain

	ipsetStore  *ipsetStore
	ipsetStore6 *ipsetStore
	rules       map[string]*Rule
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
	Address6() *iface.WGAddress
	IsUserspaceBind() bool
}

func newAclManager(table *nftables.Table, table6 *nftables.Table, wgIface iFaceMapper, routeingFwChainName string) (*AclManager, error) {
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
		workTable6:          table6,
		v6Active:            wgIface.Address6() != nil,
		routeingFwChainName: routeingFwChainName,

		ipsetStore:  newIpsetStore(),
		ipsetStore6: newIpsetStore(),
		rules:       make(map[string]*Rule),
	}

	err = m.createDefaultChains(false)
	if err != nil {
		return nil, err
	}

	if m.v6Active {
		err = m.createDefaultChains(true)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

// PrepareV6Reset prepares the ACL manager for a full V6 table reset (necessary if IPv6 address changes).
// Deletes all IPv6 rules and sets, and sets the V6 active status to false.
func (m *AclManager) PrepareV6Reset() (*nftables.Table, error) {
	if m.workTable6 != nil {
		for k, r := range m.rules {
			if r.ip.To4() == nil {
				err := m.DeleteRule(r)
				if err != nil {
					return nil, err
				}
				delete(m.rules, k)
			}
		}
		sets, err := m.rConn.GetSets(m.workTable6)
		if err != nil {
			for _, set := range sets {
				m.rConn.DelSet(set)
			}
		}
		m.ipsetStore6 = newIpsetStore()
	}
	// Set to false just in case of concurrent accesses (will be set to actual values in ReinitAfterV6Reset()).
	m.v6Active = false

	// return the current work table.
	return m.workTable6, nil
}

// ReinitAfterV6Reset reinitializes the IPv6 table after an IPv6 address change.
func (m *AclManager) ReinitAfterV6Reset(workTable6 *nftables.Table) error {
	// If we have an IPv6 address after the address update, initialize firewall table, else not.
	if m.wgIface.Address6() != nil {
		m.workTable6 = workTable6
		err := m.createDefaultChains(true)
		if err != nil {
			return err
		}
		m.v6Active = true
	} else {
		m.workTable6 = nil
		m.v6Active = false
	}
	return nil
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
	if ipsetName != "" {
		var err error
		ipset, err = m.addIpToSet(ipsetName, ip)
		if err != nil {
			return nil, err
		}
	}
	if !m.v6Active && ip.To4() == nil {
		return nil, fmt.Errorf("attempted to configure filtering for IPv6 address even though IPv6 is not active")
	}

	newRules := make([]firewall.Rule, 0, 2)
	ioRule, err := m.addIOFiltering(ip, proto, sPort, dPort, direction, action, ipset, comment)
	if err != nil {
		return nil, err
	}

	newRules = append(newRules, ioRule)
	if !shouldAddToPrerouting(proto, dPort, direction) {
		return newRules, nil
	}

	preroutingRule, err := m.addPreroutingFiltering(ipset, proto, dPort, ip)
	if err != nil {
		return newRules, err
	}
	newRules = append(newRules, preroutingRule)
	return newRules, nil
}

// DeleteRule from the firewall by rule definition
func (m *AclManager) DeleteRule(rule firewall.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	ipsetStorage := m.ipsetStore
	if r.ip.To4() == nil {
		ipsetStorage = m.ipsetStore6
	}

	if r.nftSet == nil {
		err := m.rConn.DelRule(r.nftRule)
		if err != nil {
			log.Errorf("failed to delete rule: %v", err)
		}
		delete(m.rules, r.GetRuleID())
		return m.rConn.Flush()
	}

	ips, ok := ipsetStorage.ips(r.nftSet.Name)
	if !ok {
		err := m.rConn.DelRule(r.nftRule)
		if err != nil {
			log.Errorf("failed to delete rule: %v", err)
		}
		delete(m.rules, r.GetRuleID())
		return m.rConn.Flush()
	}
	if _, ok := ips[r.ip.String()]; ok {
		rawIP := r.ip.To4()
		if rawIP == nil {
			rawIP = r.ip.To16()
		}
		err := m.sConn.SetDeleteElements(r.nftSet, []nftables.SetElement{{Key: rawIP}})
		if err != nil {
			log.Errorf("delete elements for set %q: %v", r.nftSet.Name, err)
		}
		if err := m.sConn.Flush(); err != nil {
			log.Debugf("flush error of set delete element, %s", r.nftSet.Name)
			return err
		}
		ipsetStorage.DeleteIpFromSet(r.nftSet.Name, r.ip)
	}

	// if after delete, set still contains other IPs,
	// no need to delete firewall rule and we should exit here
	if len(ips) > 0 {
		return nil
	}

	err := m.rConn.DelRule(r.nftRule)
	if err != nil {
		log.Errorf("failed to delete rule: %v", err)
	}
	err = m.rConn.Flush()
	if err != nil {
		return err
	}

	delete(m.rules, r.GetRuleID())
	ipsetStorage.DeleteReferenceFromIpSet(r.nftSet.Name)

	if ipsetStorage.HasReferenceToSet(r.nftSet.Name) {
		return nil
	}

	// we delete last IP from the set, that means we need to delete
	// set itself and associated firewall rule too
	m.rConn.FlushSet(r.nftSet)
	m.rConn.DelSet(r.nftSet)
	ipsetStorage.deleteIpset(r.nftSet.Name)
	return nil
}

// createDefaultAllowRules In case if the USP firewall manager can use the native firewall manager we must create allow rules for
// input and output chains
func (m *AclManager) createDefaultAllowRules() error {
	expIn := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		// mask
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0x00, 0x00, 0x00, 0x00},
			Xor:            zeroXor,
		},
		// net address
		&expr.Cmp{
			Register: 1,
			Data:     []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	_ = m.rConn.InsertRule(&nftables.Rule{
		Table:    m.workTable,
		Chain:    m.chainInputRules,
		Position: 0,
		Exprs:    expIn,
	})

	expOut := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		// mask
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0x00, 0x00, 0x00, 0x00},
			Xor:            zeroXor,
		},
		// net address
		&expr.Cmp{
			Register: 1,
			Data:     []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	_ = m.rConn.InsertRule(&nftables.Rule{
		Table:    m.workTable,
		Chain:    m.chainOutputRules,
		Position: 0,
		Exprs:    expOut,
	})

	err := m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create default allow rules: %s", err)
		return err
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

	if err := m.refreshRuleHandles(m.workTable, m.chainInputRules); err != nil {
		log.Errorf("failed to refresh rule handles ipv4 input chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.workTable, m.chainOutputRules); err != nil {
		log.Errorf("failed to refresh rule handles IPv4 output chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.workTable, m.chainPrerouting); err != nil {
		log.Errorf("failed to refresh rule handles IPv4 prerouting chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.workTable6, m.chainInputRules6); err != nil {
		log.Errorf("failed to refresh rule handles IPv6 input chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.workTable6, m.chainOutputRules6); err != nil {
		log.Errorf("failed to refresh rule handles IPv6 output chain: %v", err)
	}

	if err := m.refreshRuleHandles(m.workTable6, m.chainPrerouting6); err != nil {
		log.Errorf("failed to refresh rule handles IPv6 prerouting chain: %v", err)
	}

	return nil
}

func (m *AclManager) addIOFiltering(ip net.IP, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action, ipset *nftables.Set, comment string) (*Rule, error) {
	ruleId := generateRuleId(ip, sPort, dPort, direction, action, ipset)
	if r, ok := m.rules[ruleId]; ok {
		return &Rule{
			r.nftRule,
			r.nftSet,
			r.ruleID,
			ip,
		}, nil
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
		expressions = append(expressions, &expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
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

	workTable := m.workTable
	// Raw bytes of IP to match (if IPv4).
	rawIP := ip.To4()
	// source address position (in IPv4)
	srcAddrOffset := uint32(12)
	// destination address position (in IPv4)
	dstAddrOffset := uint32(16)
	// address length
	addrLen := uint32(4)
	// IP set storage for IPv4.
	ipsetStorage := m.ipsetStore

	// If rawIP == nil, we have an IPv6 address, replace previously defined values with IPv6 counterparts.
	if rawIP == nil {
		rawIP = ip.To16()
		srcAddrOffset = uint32(8)
		dstAddrOffset = uint32(24)
		addrLen = 16
		workTable = m.workTable6
		ipsetStorage = m.ipsetStore6
	}

	// check if rawIP contains zeroed IP address value
	// in that case not add IP match expression into the rule definition
	if !bytes.HasPrefix(anyIP, rawIP) {

		addrOffset := srcAddrOffset
		if direction == firewall.RuleDirectionOUT {
			addrOffset = dstAddrOffset
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

	userData := []byte(strings.Join([]string{ruleId, comment}, " "))

	var chain *nftables.Chain
	if direction == firewall.RuleDirectionIN {
		chain = m.chainInputRules
	} else {
		chain = m.chainOutputRules
	}
	nftRule := m.rConn.InsertRule(&nftables.Rule{
		Table:    workTable,
		Chain:    chain,
		Position: 0,
		Exprs:    expressions,
		UserData: userData,
	})

	rule := &Rule{
		nftRule: nftRule,
		nftSet:  ipset,
		ruleID:  ruleId,
		ip:      ip,
	}
	m.rules[ruleId] = rule
	if ipset != nil {
		ipsetStorage.AddReferenceToIpset(ipset.Name)
	}
	return rule, nil
}

func (m *AclManager) addPreroutingFiltering(ipset *nftables.Set, proto firewall.Protocol, port *firewall.Port, ip net.IP) (*Rule, error) {
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

	// Raw bytes of IP to match (if IPv4).
	rawIP := ip.To4()
	// source address position (in IPv4)
	srcAddrOffset := uint32(12)
	// destination address position (in IPv4)
	dstAddrOffset := uint32(16)
	// address length
	addrLen := uint32(4)
	// Raw bytes of the wireguard interface's IPv4 address.
	ifaceRawIP := m.wgIface.Address().IP.To4()
	// table to insert rule in
	workTable := m.workTable
	// chain to insert rule in
	preroutingChain := m.chainPrerouting
	// IP set store to use
	ipsetStorage := m.ipsetStore

	// If rawIP == nil, we have an IPv6 address, replace previously defined values with IPv6 counterparts.
	if rawIP == nil {
		rawIP = ip.To16()
		srcAddrOffset = uint32(8)
		dstAddrOffset = uint32(24)
		addrLen = 16
		ifaceRawIP = m.wgIface.Address6().IP.To16()
		workTable = m.workTable6
		preroutingChain = m.chainPrerouting6
		ipsetStorage = m.ipsetStore6
	}

	ruleId := generateRuleIdForMangle(ipset, ip, proto, port)
	if r, ok := m.rules[ruleId]; ok {
		return &Rule{
			r.nftRule,
			r.nftSet,
			r.ruleID,
			ip,
		}, nil
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
			Offset:       srcAddrOffset,
			Len:          addrLen,
		},
		ipExpression,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       dstAddrOffset,
			Len:          addrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifaceRawIP,
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
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

	nftRule := m.rConn.InsertRule(&nftables.Rule{
		Table:    workTable,
		Chain:    preroutingChain,
		Position: 0,
		Exprs:    expressions,
		UserData: []byte(ruleId),
	})

	if err := m.rConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush insert rule: %v", err)
	}

	rule := &Rule{
		nftRule: nftRule,
		nftSet:  ipset,
		ruleID:  ruleId,
		ip:      ip,
	}

	m.rules[ruleId] = rule
	if ipset != nil {
		ipsetStorage.AddReferenceToIpset(ipset.Name)
	}
	return rule, nil
}

func (m *AclManager) createDefaultChains(forV6 bool) (err error) {
	workTable := m.workTable
	if forV6 {
		workTable = m.workTable6
	}

	// chainNameInputRules
	chain := m.createChain(chainNameInputRules, workTable)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}
	chainInputRules := chain
	if forV6 {
		m.chainInputRules6 = chainInputRules
	} else {
		m.chainInputRules = chainInputRules
	}

	// chainNameOutputRules
	chain = m.createChain(chainNameOutputRules, workTable)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameOutputRules, err)
		return err
	}
	chainOutputRules := chain
	if forV6 {
		m.chainOutputRules6 = chainOutputRules
	} else {
		m.chainOutputRules = chainOutputRules
	}

	// netbird-acl-input-filter
	// type filter hook input priority filter; policy accept;
	chain = m.createFilterChainWithHook(chainNameInputFilter, nftables.ChainHookInput, workTable)
	//netbird-acl-input-filter iifname "wt0" ip saddr 100.72.0.0/16 ip daddr != 100.72.0.0/16 accept
	m.addRouteAllowRule(chain, expr.MetaKeyIIFNAME)
	m.addFwdAllow(chain, expr.MetaKeyIIFNAME)
	m.addJumpRule(chain, chainInputRules.Name, expr.MetaKeyIIFNAME) // to netbird-acl-input-rules
	m.addDropExpressions(chain, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameInputFilter, err)
		return err
	}

	// netbird-acl-output-filter
	// type filter hook output priority filter; policy accept;
	chain = m.createFilterChainWithHook(chainNameOutputFilter, nftables.ChainHookOutput, workTable)
	m.addRouteAllowRule(chain, expr.MetaKeyOIFNAME)
	m.addFwdAllow(chain, expr.MetaKeyOIFNAME)
	m.addJumpRule(chain, chainOutputRules.Name, expr.MetaKeyOIFNAME) // to netbird-acl-output-rules
	m.addDropExpressions(chain, expr.MetaKeyOIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameOutputFilter, err)
		return err
	}

	// netbird-acl-forward-filter
	chain = m.createFilterChainWithHook(chainNameForwardFilter, nftables.ChainHookForward, workTable)
	m.addJumpRulesToRtForward(workTable, chain) // to
	m.addMarkAccept(workTable, chain)
	m.addJumpRuleToInputChain(workTable, chain, chainInputRules) // to netbird-acl-input-rules
	m.addDropExpressions(chain, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameForwardFilter, err)
		return err
	}
	if forV6 {
		m.chainFwFilter6 = chain
	} else {
		m.chainFwFilter = chain
	}

	// netbird-acl-output-filter
	// type filter hook output priority filter; policy accept;
	chain = m.createPreroutingMangle(forV6)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}
	if forV6 {
		m.chainPrerouting6 = chain
	} else {
		m.chainPrerouting = chain
	}

	return nil
}

func (m *AclManager) addJumpRulesToRtForward(table *nftables.Table, chain *nftables.Chain) {

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
		Table: table,
		Chain: chain,
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
		Table: table,
		Chain: chain,
		Exprs: expressions,
	})
}

func (m *AclManager) addMarkAccept(table *nftables.Table, chain *nftables.Chain) {
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
			Table: table,
			Chain: chain,
			Exprs: expressions,
		})
	}
}

func (m *AclManager) createChain(name string, table *nftables.Table) *nftables.Chain {

	chain := &nftables.Chain{
		Name:  name,
		Table: table,
	}

	chain = m.rConn.AddChain(chain)

	return chain
}

func (m *AclManager) createFilterChainWithHook(name string, hookNum nftables.ChainHook, table *nftables.Table) *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     name,
		Table:    table,
		Hooknum:  hookNum,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	return m.rConn.AddChain(chain)
}

func (m *AclManager) createPreroutingMangle(forV6 bool) *nftables.Chain {
	workTable := m.workTable
	// Raw bytes of the wireguard interface's IPv4 address.
	rawIP := m.wgIface.Address().Network.IP.To4()
	// Subnet mask of the wireguard interface's network.
	mask := m.wgIface.Address().Network.Mask
	// Length of an IPv4 address
	addrLen := uint32(4)
	// source address position
	srcAddrOffset := uint32(12)
	// destination address position
	dstAddrOffset := uint32(16)
	// An array representing a null address in IPv4 (0.0.0.0)
	nullAddressArray := nullAddress4

	// If prerouting mangle should be created for IPv6 table, replace previously defined values with IPv6 counterparts.
	if forV6 {
		workTable = m.workTable6
		rawIP = m.wgIface.Address6().Network.IP.To16()
		mask = m.wgIface.Address6().Network.Mask
		addrLen = 16
		srcAddrOffset = uint32(8)
		dstAddrOffset = uint32(24)
		nullAddressArray = nullAddress6 // corresponds to ::
	}

	polAccept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     "netbird-acl-prerouting-filter",
		Table:    workTable,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
		Policy:   &polAccept,
	}

	chain = m.rConn.AddChain(chain)

	ip, _ := netip.AddrFromSlice(rawIP)

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
			Offset:       srcAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       dstAddrOffset,
			Len:          addrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     rawIP,
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
		Table: workTable,
		Chain: chain,
		Exprs: expressions,
	})
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
		Table: chain.Table,
		Chain: chain,
		Exprs: expressions,
	})
	return nil
}

func (m *AclManager) addJumpRuleToInputChain(table *nftables.Table, chain *nftables.Chain, inputChain *nftables.Chain) {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: inputChain.Name,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: expressions,
	})
}

func (m *AclManager) addRouteAllowRule(chain *nftables.Chain, netIfName expr.MetaKey) {
	// Raw bytes of the wireguard interface's IPv4 address.
	rawIP := m.wgIface.Address().Network.IP.To4()
	// Subnet mask of the wireguard interface's network.
	mask := m.wgIface.Address().Network.Mask
	// Length of an IPv4 address
	addrLen := uint32(4)
	// source address position
	srcAddrOffset := uint32(12)
	// destination address position
	dstAddrOffset := uint32(16)
	// An array representing a null address in IPv4 (0.0.0.0)
	nullAddressArray := nullAddress4

	// If route allow rule should be created for IPv6 table, replace previously defined values with IPv6 counterparts.
	if chain.Table.Family == nftables.TableFamilyIPv6 {
		rawIP = m.wgIface.Address6().Network.IP.To16()
		mask = m.wgIface.Address6().Network.Mask
		addrLen = 16
		srcAddrOffset = 8
		dstAddrOffset = 24
		nullAddressArray = nullAddress6 // corresponds to ::
	}

	ip, _ := netip.AddrFromSlice(rawIP)

	var srcOp, dstOp expr.CmpOp
	if netIfName == expr.MetaKeyIIFNAME {
		srcOp = expr.CmpOpEq
		dstOp = expr.CmpOpNeq
	} else {
		srcOp = expr.CmpOpNeq
		dstOp = expr.CmpOpEq
	}
	expressions := []expr.Any{
		&expr.Meta{Key: netIfName, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       srcAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
		},
		&expr.Cmp{
			Op:       srcOp,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       dstAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
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

func (m *AclManager) addFwdAllow(chain *nftables.Chain, iifname expr.MetaKey) {
	// Raw bytes of the wireguard interface's IPv4 address.
	rawIP := m.wgIface.Address().Network.IP.To4()
	// Subnet mask of the wireguard interface's network.
	mask := m.wgIface.Address().Network.Mask
	// Length of an IPv4 address
	addrLen := uint32(4)
	// source address position
	srcAddrOffset := uint32(12)
	// destination address position
	dstAddrOffset := uint32(16)
	// An array representing a null address in IPv4 (0.0.0.0)
	nullAddressArray := nullAddress4

	// If forward allow rule should be created for IPv6 table, replace previously defined values with IPv6 counterparts.
	if chain.Table.Family == nftables.TableFamilyIPv6 {
		rawIP = m.wgIface.Address6().Network.IP.To16()
		mask = m.wgIface.Address6().Network.Mask
		addrLen = 16
		srcAddrOffset = 8
		dstAddrOffset = 24
		nullAddressArray = nullAddress6 // corresponds to ::
	}

	ip, _ := netip.AddrFromSlice(rawIP)

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
			Offset:       srcAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
		},
		&expr.Cmp{
			Op:       srcOp,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       dstAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
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
	// Raw bytes of the wireguard interface's IPv4 address.
	rawIP := m.wgIface.Address().Network.IP.To4()
	// Subnet mask of the wireguard interface's network.
	mask := m.wgIface.Address().Network.Mask
	// Length of an IPv4 address
	addrLen := uint32(4)
	// source address position
	srcAddrOffset := uint32(12)
	// destination address position
	dstAddrOffset := uint32(16)
	// An array representing a null address in IPv4 (0.0.0.0)
	nullAddressArray := nullAddress4

	// If jump rule should be created for IPv6 table, replace previously defined values with IPv6 counterparts.
	if chain.Table.Family == nftables.TableFamilyIPv6 {
		rawIP = m.wgIface.Address6().Network.IP.To16()
		mask = m.wgIface.Address6().Network.Mask
		addrLen = 16
		srcAddrOffset = 8
		dstAddrOffset = 24
		nullAddressArray = nullAddress6 // corresponds to ::
	}

	ip, _ := netip.AddrFromSlice(rawIP)

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
			Offset:       srcAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ip.Unmap().AsSlice(),
		},
		&expr.Payload{
			DestRegister: 2,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       dstAddrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 2,
			DestRegister:   2,
			Len:            addrLen,
			Xor:            nullAddressArray,
			Mask:           mask,
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

func (m *AclManager) addIpToSet(ipsetName string, ip net.IP) (*nftables.Set, error) {

	workTable := m.workTable
	// Raw bytes of the IPv4 address to add
	rawIP := ip.To4()
	// Type of set to add to
	ipsetType := nftables.TypeIPAddr
	// IP set store to use
	ipsetStorage := m.ipsetStore

	// If rawIP == nil, we have an IPv6 address, replace previously defined values with IPv6 counterparts.
	if rawIP == nil {
		workTable = m.workTable6
		rawIP = ip.To16()
		ipsetType = nftables.TypeIP6Addr
		ipsetStorage = m.ipsetStore6
	}

	ipset, err := m.rConn.GetSetByName(workTable, ipsetName)
	if err != nil {
		if ipset, err = m.createSet(workTable, ipsetName, ipsetType); err != nil {
			return nil, fmt.Errorf("get set name: %v", err)
		}

		ipsetStorage.newIpset(ipset.Name)
	}

	if ipsetStorage.IsIpInSet(ipset.Name, ip) {
		return ipset, nil
	}

	if err := m.sConn.SetAddElements(ipset, []nftables.SetElement{{Key: rawIP}}); err != nil {
		return nil, fmt.Errorf("add set element for the first time: %v", err)
	}

	ipsetStorage.AddIpToSet(ipset.Name, ip)

	if err := m.sConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush add elements: %v", err)
	}

	return ipset, nil
}

// createSet in given table by name
func (m *AclManager) createSet(table *nftables.Table, name string, ipsetType nftables.SetDatatype) (*nftables.Set, error) {
	ipset := &nftables.Set{
		Name:    name,
		Table:   table,
		Dynamic: true,
		KeyType: ipsetType,
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
			backoffTime *= 2
			continue
		}
		break
	}
	return
}

func (m *AclManager) refreshRuleHandles(table *nftables.Table, chain *nftables.Chain) error {
	if table == nil || chain == nil {
		return nil
	}

	list, err := m.rConn.GetRules(table, chain)
	if err != nil {
		return err
	}

	for _, rule := range list {
		if len(rule.UserData) == 0 {
			continue
		}
		split := bytes.Split(rule.UserData, []byte(" "))
		r, ok := m.rules[string(split[0])]
		if ok {
			*r.nftRule = *rule
		}
	}

	return nil
}

func generateRuleId(
	ip net.IP,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipset *nftables.Set,
) string {
	ipver := "v4"
	if ip.To4() == nil {
		ipver = "v6"
	}
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
	return "set:" + ipver + ":" + ipset.Name + rulesetID
}
func generateRuleIdForMangle(ipset *nftables.Set, ip net.IP, proto firewall.Protocol, port *firewall.Port) string {
	// case of icmp port is empty
	var p string
	if port != nil {
		p = port.String()
	}
	ipver := "v4"
	if (ipset != nil && ipset.Table.Family == nftables.TableFamilyIPv6) || ip.To4() == nil {
		ipver = "v6"
	}
	if ipset != nil {
		return fmt.Sprintf("p:set:%s:%s:%s:%v", ipver, ipset.Name, proto, p)
	} else {
		return fmt.Sprintf("p:ip:%s:%s:%s:%v", ipver, ip.String(), proto, p)
	}
}

func shouldAddToPrerouting(proto firewall.Protocol, dPort *firewall.Port, direction firewall.RuleDirection) bool {
	if proto == "all" {
		return false
	}

	if direction != firewall.RuleDirectionIN {
		return false
	}

	if dPort == nil && proto != firewall.ProtocolICMP {
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
