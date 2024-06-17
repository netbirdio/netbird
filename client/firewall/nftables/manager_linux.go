package nftables

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

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

	err := m.aclManager.createDefaultAllowRules()
	if err != nil {
		return fmt.Errorf("failed to create default allow rules: %v", err)
	}

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

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.rConn.ListChains()
	if err != nil {
		return fmt.Errorf("list of chains: %w", err)
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
	}

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
