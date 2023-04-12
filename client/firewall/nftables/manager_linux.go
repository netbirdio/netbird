package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall"
)

const (
	// FilterTableName is the name of the table that is used for filtering by the Netbird client
	FilterTableName = "netbird-acl"

	// FilterChainName is the name of the chain that is used for filtering by the Netbird client
	FilterChainName = "netbird-acl-filter"
)

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	conn      *nftables.Conn
	tableIPv4 *nftables.Table
	tableIPv6 *nftables.Table

	filterChainIPv4 *nftables.Chain
	filterChainIPv6 *nftables.Chain

	wgIfaceName string
}

func Create(wgIfaceName string) (*Manager, error) {
	m := &Manager{
		conn:        &nftables.Conn{},
		wgIfaceName: wgIfaceName,
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
	port *fw.Port,
	direction fw.Direction,
	action fw.Action,
	comment string,
) (fw.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// get filter chain
	table, chain, err := m.chain(
		ip,
		FilterChainName,
		nftables.ChainHookOutput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)
	if err != nil {
		return nil, err
	}

	expressions := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       uint32(9),
			Len:          uint32(1),
		},
	}

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

	// source address position
	var adrLen, adrOffset uint32
	if ip.To4() == nil {
		adrLen = 16
		adrOffset = 8
	} else {
		adrLen = 4
		adrOffset = 12
	}

	// change to destination address position if need
	if direction == fw.DirectionDst {
		adrOffset += adrLen
	}

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()

	expressions = append(expressions,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       adrOffset,
			Len:          adrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     add.AsSlice(),
		},
	)

	if port != nil && len(port.Values) != 0 {
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
				Data:     encodePort(*port),
			},
		)
	}

	id := uuid.New().String()
	userData := []byte(strings.Join([]string{id, comment}, " "))

	_ = m.conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    expressions,
		UserData: userData,
	})

	if err := m.conn.Flush(); err != nil {
		return nil, err
	}

	list, err := m.conn.GetRules(table, chain)
	if err != nil {
		return nil, err
	}

	// Add the rule to the chain
	rule := &Rule{id: uuid.New().String()}
	for _, r := range list {
		if bytes.Equal(r.UserData, userData) {
			rule.Rule = r
			break
		}
	}
	if rule.Rule == nil {
		return nil, fmt.Errorf("rule not found")
	}

	return rule, nil
}

// chain returns the chain for the given IP address with specific settings
func (m *Manager) chain(
	ip net.IP,
	name string,
	hook nftables.ChainHook,
	priority nftables.ChainPriority,
	cType nftables.ChainType,
) (*nftables.Table, *nftables.Chain, error) {
	if ip.To4() != nil {
		if m.filterChainIPv4 != nil {
			return m.tableIPv4, m.filterChainIPv4, nil
		}

		chain, err := m.createChainIfNotExists(
			nftables.TableFamilyIPv4,
			name,
			hook,
			priority,
			cType,
		)
		if err != nil {
			return nil, nil, err
		}
		m.filterChainIPv4 = chain
		return m.tableIPv4, m.filterChainIPv4, nil
	}
	if m.filterChainIPv6 != nil {
		return m.tableIPv4, m.filterChainIPv6, nil
	}

	chain, err := m.createChainIfNotExists(
		nftables.TableFamilyIPv6,
		name,
		hook,
		priority,
		cType,
	)
	if err != nil {
		return nil, nil, err
	}
	m.filterChainIPv6 = chain
	return m.tableIPv6, m.filterChainIPv6, nil
}

// table returns the table for the given family of the IP address
func (m *Manager) table(family nftables.TableFamily) (*nftables.Table, error) {
	if family == nftables.TableFamilyIPv4 {
		if m.tableIPv4 != nil {
			return m.tableIPv4, nil
		}

		table, err := m.createTableIfNotExists(nftables.TableFamilyIPv4)
		if err != nil {
			return nil, err
		}
		m.tableIPv4 = table
		return m.tableIPv4, nil
	}

	if m.tableIPv6 != nil {
		return m.tableIPv6, nil
	}

	table, err := m.createTableIfNotExists(nftables.TableFamilyIPv6)
	if err != nil {
		return nil, err
	}
	m.tableIPv6 = table
	return m.tableIPv6, nil
}

func (m *Manager) createTableIfNotExists(family nftables.TableFamily) (*nftables.Table, error) {
	tables, err := m.conn.ListTablesOfFamily(family)
	if err != nil {
		return nil, fmt.Errorf("list of tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == FilterTableName {
			return t, nil
		}
	}

	return m.conn.AddTable(&nftables.Table{Name: FilterTableName, Family: nftables.TableFamilyIPv4}), nil
}

func (m *Manager) createChainIfNotExists(
	family nftables.TableFamily,
	name string,
	hooknum nftables.ChainHook,
	priority nftables.ChainPriority,
	chainType nftables.ChainType,
) (*nftables.Chain, error) {
	table, err := m.table(family)
	if err != nil {
		return nil, err
	}

	chains, err := m.conn.ListChainsOfTableFamily(family)
	if err != nil {
		return nil, fmt.Errorf("list of chains: %w", err)
	}

	for _, c := range chains {
		if c.Name == FilterChainName && c.Table.Name == table.Name {
			return c, nil
		}
	}

	chain := nftables.Chain{
		Name: FilterChainName, Table: table, Hooknum: hooknum, Priority: priority, Type: chainType,
	}
	return m.conn.AddChain(&chain), nil

}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule fw.Rule) error {
	nativeRule, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("invalid rule type")
	}

	if err := m.conn.DelRule(nativeRule.Rule); err != nil {
		return err
	}

	return m.conn.Flush()
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.conn.ListChains()
	if err != nil {
		return fmt.Errorf("list of chains: %w", err)
	}
	for _, c := range chains {
		if c.Name == FilterChainName {
			m.conn.DelChain(c)
		}
	}

	tables, err := m.conn.ListTables()
	if err != nil {
		return fmt.Errorf("list of tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == FilterTableName {
			m.conn.DelTable(t)
		}
	}

	return m.conn.Flush()
}

func encodePort(port fw.Port) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(port.Values[0]))
	return bs
}
