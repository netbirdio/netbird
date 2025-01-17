package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

const (

	// rules chains contains the effective ACL rules
	chainNameInputRules = "netbird-acl-input-rules"

	// filter chains contains the rules that jump to the rules chains
	chainNameInputFilter   = "netbird-acl-input-filter"
	chainNameForwardFilter = "netbird-acl-forward-filter"
	chainNamePrerouting    = "netbird-rt-prerouting"

	allowNetbirdInputRuleID = "allow Netbird incoming traffic"
)

const flushError = "flush: %w"

var (
	anyIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

type AclManager struct {
	rConn              *nftables.Conn
	sConn              *nftables.Conn
	wgIface            iFaceMapper
	routingFwChainName string

	workTable       *nftables.Table
	chainInputRules *nftables.Chain

	ipsetStore *ipsetStore
	rules      map[string]*Rule
}

func newAclManager(table *nftables.Table, wgIface iFaceMapper, routingFwChainName string) (*AclManager, error) {
	// sConn is used for creating sets and adding/removing elements from them
	// it's differ then rConn (which does create new conn for each flush operation)
	// and is permanent. Using same connection for both type of operations
	// overloads netlink with high amount of rules ( > 10000)
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("create nf conn: %w", err)
	}

	return &AclManager{
		rConn:              &nftables.Conn{},
		sConn:              sConn,
		wgIface:            wgIface,
		workTable:          table,
		routingFwChainName: routingFwChainName,

		ipsetStore: newIpsetStore(),
		rules:      make(map[string]*Rule),
	}, nil
}

func (m *AclManager) init(workTable *nftables.Table) error {
	m.workTable = workTable
	return m.createDefaultChains()
}

// AddPeerFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *AclManager) AddPeerFiltering(
	ip net.IP,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
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

	newRules := make([]firewall.Rule, 0, 2)
	ioRule, err := m.addIOFiltering(ip, proto, sPort, dPort, action, ipset, comment)
	if err != nil {
		return nil, err
	}

	newRules = append(newRules, ioRule)
	return newRules, nil
}

// DeletePeerRule from the firewall by rule definition
func (m *AclManager) DeletePeerRule(rule firewall.Rule) error {
	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	if r.nftSet == nil {
		err := m.rConn.DelRule(r.nftRule)
		if err != nil {
			log.Errorf("failed to delete rule: %v", err)
		}
		delete(m.rules, r.GetRuleID())
		return m.rConn.Flush()
	}

	ips, ok := m.ipsetStore.ips(r.nftSet.Name)
	if !ok {
		err := m.rConn.DelRule(r.nftRule)
		if err != nil {
			log.Errorf("failed to delete rule: %v", err)
		}
		delete(m.rules, r.GetRuleID())
		return m.rConn.Flush()
	}
	if _, ok := ips[r.ip.String()]; ok {
		err := m.sConn.SetDeleteElements(r.nftSet, []nftables.SetElement{{Key: r.ip.To4()}})
		if err != nil {
			log.Errorf("delete elements for set %q: %v", r.nftSet.Name, err)
		}
		if err := m.sConn.Flush(); err != nil {
			log.Debugf("flush error of set delete element, %s", r.nftSet.Name)
			return err
		}
		m.ipsetStore.DeleteIpFromSet(r.nftSet.Name, r.ip)
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
	m.ipsetStore.DeleteReferenceFromIpSet(r.nftSet.Name)

	if m.ipsetStore.HasReferenceToSet(r.nftSet.Name) {
		return nil
	}

	// we delete last IP from the set, that means we need to delete
	// set itself and associated firewall rule too
	m.rConn.FlushSet(r.nftSet)
	m.rConn.DelSet(r.nftSet)
	m.ipsetStore.deleteIpset(r.nftSet.Name)
	return nil
}

// createDefaultAllowRules creates default allow rules for the input and output chains
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
			Mask:           []byte{0, 0, 0, 0},
			Xor:            []byte{0, 0, 0, 0},
		},
		// net address
		&expr.Cmp{
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
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

	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
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

	if err := m.refreshRuleHandles(m.chainInputRules); err != nil {
		log.Errorf("failed to refresh rule handles ipv4 input chain: %v", err)
	}

	return nil
}

func (m *AclManager) addIOFiltering(
	ip net.IP,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
	ipset *nftables.Set,
	comment string,
) (*Rule, error) {
	ruleId := generatePeerRuleId(ip, sPort, dPort, action, ipset)
	if r, ok := m.rules[ruleId]; ok {
		return &Rule{
			r.nftRule,
			r.nftSet,
			r.ruleID,
			ip,
		}, nil
	}

	var expressions []expr.Any

	if proto != firewall.ProtocolALL {
		expressions = append(expressions, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       uint32(9),
			Len:          uint32(1),
		})

		protoData, err := protoToInt(proto)
		if err != nil {
			return nil, fmt.Errorf("convert protocol to number: %v", err)
		}

		expressions = append(expressions, &expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{protoData},
		})
	}

	rawIP := ip.To4()
	// check if rawIP contains zeroed IPv4 0.0.0.0 value
	// in that case not add IP match expression into the rule definition
	if !bytes.HasPrefix(anyIP, rawIP) {
		// source address position
		addrOffset := uint32(12)

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

	userData := []byte(strings.Join([]string{ruleId, comment}, " "))

	chain := m.chainInputRules
	nftRule := m.rConn.AddRule(&nftables.Rule{
		Table:    m.workTable,
		Chain:    chain,
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
		m.ipsetStore.AddReferenceToIpset(ipset.Name)
	}
	return rule, nil
}

func (m *AclManager) createDefaultChains() (err error) {
	// chainNameInputRules
	chain := m.createChain(chainNameInputRules)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return fmt.Errorf(flushError, err)
	}
	m.chainInputRules = chain

	// netbird-acl-input-filter
	// type filter hook input priority filter; policy accept;
	chain = m.createFilterChainWithHook(chainNameInputFilter, nftables.ChainHookInput)
	m.addJumpRule(chain, m.chainInputRules.Name, expr.MetaKeyIIFNAME) // to netbird-acl-input-rules
	m.addDropExpressions(chain, expr.MetaKeyIIFNAME)
	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chain.Name, err)
		return err
	}

	// netbird-acl-forward-filter
	chainFwFilter := m.createFilterChainWithHook(chainNameForwardFilter, nftables.ChainHookForward)
	m.addJumpRulesToRtForward(chainFwFilter) // to netbird-rt-fwd
	m.addDropExpressions(chainFwFilter, expr.MetaKeyIIFNAME)

	err = m.rConn.Flush()
	if err != nil {
		log.Debugf("failed to create chain (%s): %s", chainNameForwardFilter, err)
		return fmt.Errorf(flushError, err)
	}

	if err := m.allowRedirectedTraffic(chainFwFilter); err != nil {
		log.Errorf("failed to allow redirected traffic: %s", err)
	}

	return nil
}

// Makes redirected traffic originally destined for the host itself (now subject to the forward filter)
// go through the input filter as well. This will enable e.g. Docker services to keep working by accessing the
// netbird peer IP.
func (m *AclManager) allowRedirectedTraffic(chainFwFilter *nftables.Chain) error {
	preroutingChain := m.rConn.AddChain(&nftables.Chain{
		Name:     chainNamePrerouting,
		Table:    m.workTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})

	m.addPreroutingRule(preroutingChain)

	m.addFwmarkToForward(chainFwFilter)

	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	return nil
}

func (m *AclManager) addPreroutingRule(preroutingChain *nftables.Chain) {
	m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: preroutingChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(m.wgIface.Name()),
			},
			&expr.Fib{
				Register:       1,
				ResultADDRTYPE: true,
				FlagDADDR:      true,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
			},
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkRedirected),
			},
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				Register:       1,
				SourceRegister: true,
			},
		},
	})
}

func (m *AclManager) addFwmarkToForward(chainFwFilter *nftables.Chain) {
	m.rConn.InsertRule(&nftables.Rule{
		Table: m.workTable,
		Chain: chainFwFilter,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(nbnet.PreroutingFwmarkRedirected),
			},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: m.chainInputRules.Name,
			},
		},
	})
}

func (m *AclManager) addJumpRulesToRtForward(chainFwFilter *nftables.Chain) {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(m.wgIface.Name()),
		},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: m.routingFwChainName,
		},
	}

	_ = m.rConn.AddRule(&nftables.Rule{
		Table: m.workTable,
		Chain: chainFwFilter,
		Exprs: expressions,
	})
}

func (m *AclManager) createChain(name string) *nftables.Chain {
	chain := &nftables.Chain{
		Name:  name,
		Table: m.workTable,
	}

	chain = m.rConn.AddChain(chain)

	insertReturnTrafficRule(m.rConn, m.workTable, chain)

	return chain
}

func (m *AclManager) createFilterChainWithHook(name string, hookNum *nftables.ChainHook) *nftables.Chain {
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

func (m *AclManager) addJumpRule(chain *nftables.Chain, to string, ifaceKey expr.MetaKey) {
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

func (m *AclManager) addIpToSet(ipsetName string, ip net.IP) (*nftables.Set, error) {
	ipset, err := m.rConn.GetSetByName(m.workTable, ipsetName)
	rawIP := ip.To4()
	if err != nil {
		if ipset, err = m.createSet(m.workTable, ipsetName); err != nil {
			return nil, fmt.Errorf("get set name: %v", err)
		}

		m.ipsetStore.newIpset(ipset.Name)
	}

	if m.ipsetStore.IsIpInSet(ipset.Name, ip) {
		return ipset, nil
	}

	if err := m.sConn.SetAddElements(ipset, []nftables.SetElement{{Key: rawIP}}); err != nil {
		return nil, fmt.Errorf("add set element for the first time: %v", err)
	}

	m.ipsetStore.AddIpToSet(ipset.Name, ip)

	if err := m.sConn.Flush(); err != nil {
		return nil, fmt.Errorf("flush add elements: %v", err)
	}

	return ipset, nil
}

// createSet in given table by name
func (m *AclManager) createSet(table *nftables.Table, name string) (*nftables.Set, error) {
	ipset := &nftables.Set{
		Name:    name,
		Table:   table,
		Dynamic: true,
		KeyType: nftables.TypeIPAddr,
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

func (m *AclManager) refreshRuleHandles(chain *nftables.Chain) error {
	if m.workTable == nil || chain == nil {
		return nil
	}

	list, err := m.rConn.GetRules(m.workTable, chain)
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

func generatePeerRuleId(ip net.IP, sPort *firewall.Port, dPort *firewall.Port, action firewall.Action, ipset *nftables.Set) string {
	rulesetID := ":"
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

func encodePort(port firewall.Port) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(port.Values[0]))
	return bs
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

func protoToInt(protocol firewall.Protocol) (uint8, error) {
	switch protocol {
	case firewall.ProtocolTCP:
		return unix.IPPROTO_TCP, nil
	case firewall.ProtocolUDP:
		return unix.IPPROTO_UDP, nil
	case firewall.ProtocolICMP:
		return unix.IPPROTO_ICMP, nil
	}

	return 0, fmt.Errorf("unsupported protocol: %s", protocol)
}
