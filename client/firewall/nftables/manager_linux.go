package nftables

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	// tableNameNetbird is the name of the table that is used for filtering by the Netbird client
	tableNameNetbird = "netbird"

	tableNameFilter = "filter"
	chainNameInput  = "INPUT"
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

	m.router, err = newRouter(context, workTable, wgIface)
	if err != nil {
		return nil, err
	}

	m.aclManager, err = newAclManager(workTable, wgIface, chainNameRoutingFw)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// AddPeerFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *Manager) AddPeerFiltering(
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

	return m.aclManager.AddPeerFiltering(ip, proto, sPort, dPort, direction, action, ipsetName, comment)
}

func (m *Manager) AddRouteFiltering(sources []netip.Prefix, destination netip.Prefix, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !destination.Addr().Is4() {
		return nil, fmt.Errorf("unsupported IP version: %s", destination.Addr().String())
	}

	return m.router.AddRouteFiltering(sources, destination, proto, sPort, dPort, direction, action)
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclManager.DeletePeerRule(rule)
}

// DeleteRouteRule deletes a routing rule
func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.DeleteRouteRule(rule)
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) AddNatRule(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.AddNatRule(pair)
}

func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.RemoveNatRule(pair)
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
		if c.Table.Name == tableNameFilter && c.Name == chainNameForward {
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

// SetLegacyManagement sets the route manager to use legacy management
func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	oldLegacy := m.router.legacyManagement

	if oldLegacy != isLegacy {
		m.router.legacyManagement = isLegacy
		log.Debugf("Set legacy management to %v", isLegacy)
	}

	// client reconnected to a newer mgmt, we need to cleanup the legacy rules
	if !isLegacy && oldLegacy {
		if err := m.router.RemoveAllLegacyRouteRules(); err != nil {
			return fmt.Errorf("remove legacy routing rules: %v", err)
		}

		log.Debugf("Legacy routing rules removed")
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

	if err := m.router.Reset(); err != nil {
		return fmt.Errorf("reset forward rules: %v", err)
	}

	tables, err := m.rConn.ListTables()
	if err != nil {
		return fmt.Errorf("list of tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == tableNameNetbird {
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
		if t.Name == tableNameNetbird {
			m.rConn.DelTable(t)
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: tableNameNetbird, Family: nftables.TableFamilyIPv4})
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
			&expr.Verdict{},
		},
		UserData: []byte(allowNetbirdInputRuleID),
	}
	_ = m.rConn.InsertRule(rule)
}

func (m *Manager) detectAllowNetbirdRule(existedRules []*nftables.Rule) *nftables.Rule {
	ifName := ifname(m.wgIface.Name())
	for _, rule := range existedRules {
		if rule.Table.Name == tableNameFilter && rule.Chain.Name == chainNameInput {
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

func insertReturnTrafficRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) {
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	conn.InsertRule(rule)
}
