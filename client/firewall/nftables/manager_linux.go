package nftables

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
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
	if err := m.conn.Flush(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *Manager) filterChain(ip net.IP) (*nftables.Table, *nftables.Chain, error) {
	if ip.To4() != nil {
		if m.filterChainIPv4 != nil {
			return m.tableIPv4, m.filterChainIPv4, nil
		}

		chain, err := m.createChainIfNotExists(
			nftables.TableFamilyIPv4,
			FilterChainName,
			nftables.ChainHookInput+1,
			nftables.ChainPriorityFirst,
			nftables.ChainTypeFilter,
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
		FilterChainName,
		nftables.ChainHookInput+1,
		nftables.ChainPriorityFirst,
		nftables.ChainTypeFilter,
	)
	if err != nil {
		return nil, nil, err
	}
	m.filterChainIPv6 = chain
	return m.tableIPv6, m.filterChainIPv6, nil
}

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
	return fmt.Errorf("not implemented")
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	return fmt.Errorf("not implemented")
}
