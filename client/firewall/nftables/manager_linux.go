package nftables

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	// tableName is the name of the table that is used for filtering by the Netbird client
	tableName = "netbird"
)

// Manager of iptables firewall
type Manager struct {
	mutex   sync.Mutex
	rConn   *nftables.Conn
	wgIface iFaceMapper

	router     *router
	aclManager *AclManager
}

// Create nftables firewall manager
func Create(context context.Context, wgIface iFaceMapper) (*Manager, error) {
	m := &Manager{
		rConn:   &nftables.Conn{},
		wgIface: wgIface,
	}

	workTable, err := m.createWorkTable()
	if err != nil {
		return nil, err
	}

	m.router, err = newRouter(context, workTable)
	if err != nil {
		return nil, err
	}

	m.aclManager, err = newAclManager(workTable, wgIface, m.router.RouteingFwChainName())
	if err != nil {
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
) ([]firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	rawIP := ip.To4()
	if rawIP == nil {
		return nil, fmt.Errorf("unsupported IP version: %s", ip.String())
	}

	return m.aclManager.AddFiltering(ip, proto, sPort, dPort, direction, action, ipsetName, comment)
}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclManager.DeleteRule(rule)
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) InsertRoutingRules(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.InsertRoutingRules(pair)
}

func (m *Manager) RemoveRoutingRules(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.RemoveRoutingRules(pair)
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if !m.wgIface.IsUserspaceBind() {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclManager.CreateDefaultAllowRules()
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.router.ResetForwardRules()

	tables, err := m.rConn.ListTables()
	if err != nil {
		return fmt.Errorf("list of tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}

	return m.rConn.Flush()
}

// Flush rule/chain/set operations from the buffer
//
// Method also get all rules after flush and refreshes handle values in the rulesets
// todo review this method usage
func (m *Manager) Flush() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclManager.Flush()
}

func (m *Manager) createWorkTable() (*nftables.Table, error) {
	tables, err := m.rConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("list of tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4})
	err = m.rConn.Flush()
	return table, err
}
