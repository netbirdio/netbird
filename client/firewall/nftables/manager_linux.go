package nftables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	// tableNameNetbird is the default name of the table that is used for filtering by the Netbird client
	tableNameNetbird = "netbird"
	// envTableName is the environment variable to override the table name
	envTableName = "NB_NFTABLES_TABLE"

	tableNameFilter = "filter"
	chainNameInput  = "INPUT"
)

func getTableName() string {
	if name := os.Getenv(envTableName); name != "" {
		return name
	}
	return tableNameNetbird
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() wgaddr.Address
	IsUserspaceBind() bool
}

// Manager of iptables firewall
type Manager struct {
	mutex   sync.Mutex
	rConn   *nftables.Conn
	wgIface iFaceMapper

	router                 *router
	aclManager             *AclManager
	notrackOutputChain     *nftables.Chain
	notrackPreroutingChain *nftables.Chain
}

// Create nftables firewall manager
func Create(wgIface iFaceMapper, mtu uint16) (*Manager, error) {
	m := &Manager{
		rConn:   &nftables.Conn{},
		wgIface: wgIface,
	}

	workTable := &nftables.Table{Name: getTableName(), Family: nftables.TableFamilyIPv4}

	var err error
	m.router, err = newRouter(workTable, wgIface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	m.aclManager, err = newAclManager(workTable, wgIface, chainNameRoutingFw)
	if err != nil {
		return nil, fmt.Errorf("create acl manager: %w", err)
	}

	return m, nil
}

// Init nftables firewall manager
func (m *Manager) Init(stateManager *statemanager.Manager) error {
	workTable, err := m.createWorkTable()
	if err != nil {
		return fmt.Errorf("create work table: %w", err)
	}

	if err := m.router.init(workTable); err != nil {
		return fmt.Errorf("router init: %w", err)
	}

	if err := m.aclManager.init(workTable); err != nil {
		// TODO: cleanup router
		return fmt.Errorf("acl manager init: %w", err)
	}

	if err := m.initNoTrackChains(workTable); err != nil {
		return fmt.Errorf("init notrack chains: %w", err)
	}

	stateManager.RegisterState(&ShutdownState{})

	// We only need to record minimal interface state for potential recreation.
	// Unlike iptables, which requires tracking individual rules, nftables maintains
	// a known state (our netbird table plus a few static rules). This allows for easy
	// cleanup using Close() without needing to store specific rules.
	if err := stateManager.UpdateState(&ShutdownState{
		InterfaceState: &InterfaceState{
			NameStr:       m.wgIface.Name(),
			WGAddress:     m.wgIface.Address(),
			UserspaceBind: m.wgIface.IsUserspaceBind(),
			MTU:           m.router.mtu,
		},
	}); err != nil {
		log.Errorf("failed to update state: %v", err)
	}

	// persist early
	go func() {
		if err := stateManager.PersistState(context.Background()); err != nil {
			log.Errorf("failed to persist state: %v", err)
		}
	}()

	return nil
}

// AddPeerFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *Manager) AddPeerFiltering(
	id []byte,
	ip net.IP,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
	ipsetName string,
) ([]firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	rawIP := ip.To4()
	if rawIP == nil {
		return nil, fmt.Errorf("unsupported IP version: %s", ip.String())
	}

	return m.aclManager.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
}

func (m *Manager) AddRouteFiltering(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if destination.IsPrefix() && !destination.Prefix.Addr().Is4() {
		return nil, fmt.Errorf("unsupported IP version: %s", destination.Prefix.Addr().String())
	}

	return m.router.AddRouteFiltering(id, sources, destination, proto, sPort, dPort, action)
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

func (m *Manager) IsStateful() bool {
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

	if err := m.aclManager.createDefaultAllowRules(); err != nil {
		return fmt.Errorf("create default allow rules: %w", err)
	}
	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf("flush allow input netbird rules: %w", err)
	}

	return nil
}

// SetLegacyManagement sets the route manager to use legacy management
func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	return firewall.SetLegacyManagement(m.router, isLegacy)
}

// Close closes the firewall manager
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.router.Reset(); err != nil {
		return fmt.Errorf("reset router: %v", err)
	}

	if err := m.cleanupNetbirdTables(); err != nil {
		return fmt.Errorf("cleanup netbird tables: %v", err)
	}

	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	if err := stateManager.DeleteState(&ShutdownState{}); err != nil {
		return fmt.Errorf("delete state: %v", err)
	}

	return nil
}

func (m *Manager) cleanupNetbirdTables() error {
	tables, err := m.rConn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	tableName := getTableName()
	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}
	return nil
}

// SetLogLevel sets the log level for the firewall manager
func (m *Manager) SetLogLevel(log.Level) {
	// not supported
}

func (m *Manager) EnableRouting() error {
	if err := m.router.ipFwdState.RequestForwarding(); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}
	return nil
}

func (m *Manager) DisableRouting() error {
	if err := m.router.ipFwdState.ReleaseForwarding(); err != nil {
		return fmt.Errorf("disable IP forwarding: %w", err)
	}
	return nil
}

// Flush rule/chain/set operations from the buffer
//
// Method also get all rules after flush and refreshes handle values in the rulesets
// todo review this method usage
func (m *Manager) Flush() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.aclManager.Flush(); err != nil {
		return err
	}

	if err := m.refreshNoTrackChains(); err != nil {
		log.Errorf("failed to refresh notrack chains: %v", err)
	}

	return nil
}

// AddDNATRule adds a DNAT rule
func (m *Manager) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.AddDNATRule(rule)
}

// DeleteDNATRule deletes a DNAT rule
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.DeleteDNATRule(rule)
}

// UpdateSet updates the set with the given prefixes
func (m *Manager) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.UpdateSet(set, prefixes)
}

// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services.
func (m *Manager) AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.AddInboundDNAT(localAddr, protocol, sourcePort, targetPort)
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (m *Manager) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.RemoveInboundDNAT(localAddr, protocol, sourcePort, targetPort)
}

const (
	chainNameRawOutput     = "netbird-raw-out"
	chainNameRawPrerouting = "netbird-raw-pre"
)

// SetupEBPFProxyNoTrack creates notrack rules for eBPF proxy loopback traffic.
// This prevents conntrack from tracking WireGuard proxy traffic on loopback, which
// can interfere with MASQUERADE rules (e.g., from container runtimes like Podman/netavark).
//
// Traffic flows that need NOTRACK:
//
//  1. Egress: WireGuard -> fake endpoint (before eBPF rewrite)
//     src=127.0.0.1:wgPort -> dst=127.0.0.1:fakePort
//     Matched by: sport=wgPort
//
//  2. Egress: Proxy -> WireGuard (via raw socket)
//     src=127.0.0.1:fakePort -> dst=127.0.0.1:wgPort
//     Matched by: dport=wgPort
//
//  3. Ingress: Packets to WireGuard
//     dst=127.0.0.1:wgPort
//     Matched by: dport=wgPort
//
//  4. Ingress: Packets to proxy (after eBPF rewrite)
//     dst=127.0.0.1:proxyPort
//     Matched by: dport=proxyPort
//
// Rules are cleaned up when the firewall manager is closed.
func (m *Manager) SetupEBPFProxyNoTrack(proxyPort, wgPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.notrackOutputChain == nil || m.notrackPreroutingChain == nil {
		return fmt.Errorf("notrack chains not initialized")
	}

	proxyPortBytes := binaryutil.BigEndian.PutUint16(proxyPort)
	wgPortBytes := binaryutil.BigEndian.PutUint16(wgPort)
	loopback := []byte{127, 0, 0, 1}

	// Egress rules: match outgoing loopback UDP packets
	m.rConn.AddRule(&nftables.Rule{
		Table: m.notrackOutputChain.Table,
		Chain: m.notrackOutputChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgPortBytes}, // sport=wgPort
			&expr.Counter{},
			&expr.Notrack{},
		},
	})
	m.rConn.AddRule(&nftables.Rule{
		Table: m.notrackOutputChain.Table,
		Chain: m.notrackOutputChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgPortBytes}, // dport=wgPort
			&expr.Counter{},
			&expr.Notrack{},
		},
	})

	// Ingress rules: match incoming loopback UDP packets
	m.rConn.AddRule(&nftables.Rule{
		Table: m.notrackPreroutingChain.Table,
		Chain: m.notrackPreroutingChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgPortBytes}, // dport=wgPort
			&expr.Counter{},
			&expr.Notrack{},
		},
	})
	m.rConn.AddRule(&nftables.Rule{
		Table: m.notrackPreroutingChain.Table,
		Chain: m.notrackPreroutingChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loopback},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: proxyPortBytes}, // dport=proxyPort
			&expr.Counter{},
			&expr.Notrack{},
		},
	})

	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf("flush notrack rules: %w", err)
	}

	log.Debugf("set up ebpf proxy notrack rules for ports %d,%d", proxyPort, wgPort)
	return nil
}

func (m *Manager) initNoTrackChains(table *nftables.Table) error {
	m.notrackOutputChain = m.rConn.AddChain(&nftables.Chain{
		Name:     chainNameRawOutput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityRaw,
	})

	m.notrackPreroutingChain = m.rConn.AddChain(&nftables.Chain{
		Name:     chainNameRawPrerouting,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRaw,
	})

	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf("flush chain creation: %w", err)
	}

	return nil
}

func (m *Manager) refreshNoTrackChains() error {
	chains, err := m.rConn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	tableName := getTableName()
	for _, c := range chains {
		if c.Table.Name != tableName {
			continue
		}
		switch c.Name {
		case chainNameRawOutput:
			m.notrackOutputChain = c
		case chainNameRawPrerouting:
			m.notrackPreroutingChain = c
		}
	}

	return nil
}

func (m *Manager) createWorkTable() (*nftables.Table, error) {
	tables, err := m.rConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("list of tables: %w", err)
	}

	tableName := getTableName()
	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: getTableName(), Family: nftables.TableFamilyIPv4})
	err = m.rConn.Flush()
	return table, err
}

func insertReturnTrafficRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) {
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: getEstablishedExprs(1),
	}

	conn.InsertRule(rule)
}

func getEstablishedExprs(register uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: register,
		},
		&expr.Bitwise{
			SourceRegister: register,
			DestRegister:   register,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: register,
			Data:     []byte{0, 0, 0, 0},
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}
}
