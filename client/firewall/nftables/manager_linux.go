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
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
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
}

// Manager of iptables firewall
type Manager struct {
	mutex   sync.Mutex
	rConn   *nftables.Conn
	wgIface iFaceMapper

	router     *router
	aclManager *AclManager

	// IPv6 counterparts, nil when no v6 overlay
	router6     *router
	aclManager6 *AclManager

	notrackOutputChain     *nftables.Chain
	notrackPreroutingChain *nftables.Chain

	extMonitor *externalChainMonitor
}

// Create nftables firewall manager
func Create(wgIface iFaceMapper, mtu uint16) (*Manager, error) {
	m := &Manager{
		rConn:   &nftables.Conn{},
		wgIface: wgIface,
	}

	tableName := getTableName()
	workTable := &nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4}

	var err error
	m.router, err = newRouter(workTable, wgIface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	m.aclManager, err = newAclManager(workTable, wgIface, chainNameRoutingFw)
	if err != nil {
		return nil, fmt.Errorf("create acl manager: %w", err)
	}

	if wgIface.Address().HasIPv6() {
		if err := m.createIPv6Components(tableName, wgIface, mtu); err != nil {
			return nil, fmt.Errorf("create IPv6 firewall: %w", err)
		}
	}

	m.extMonitor = newExternalChainMonitor(m)

	return m, nil
}

func (m *Manager) createIPv6Components(tableName string, wgIface iFaceMapper, mtu uint16) error {
	workTable6 := &nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv6}

	var err error
	m.router6, err = newRouter(workTable6, wgIface, mtu)
	if err != nil {
		return fmt.Errorf("create v6 router: %w", err)
	}

	// Share the same IP forwarding state with the v4 router, since
	// EnableIPForwarding controls both v4 and v6 sysctls.
	m.router6.ipFwdState = m.router.ipFwdState

	m.aclManager6, err = newAclManager(workTable6, wgIface, chainNameRoutingFw)
	if err != nil {
		return fmt.Errorf("create v6 acl manager: %w", err)
	}

	return nil
}

// hasIPv6 reports whether the manager has IPv6 components initialized.
func (m *Manager) hasIPv6() bool {
	return m.router6 != nil
}

func (m *Manager) initIPv6() error {
	workTable6, err := m.createWorkTableFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return fmt.Errorf("create v6 work table: %w", err)
	}

	if err := m.router6.init(workTable6); err != nil {
		return fmt.Errorf("v6 router init: %w", err)
	}

	if err := m.aclManager6.init(workTable6); err != nil {
		return fmt.Errorf("v6 acl manager init: %w", err)
	}

	return nil
}

// Init nftables firewall manager
func (m *Manager) Init(stateManager *statemanager.Manager) error {
	if err := m.initFirewall(); err != nil {
		return err
	}

	m.persistState(stateManager)

	// Start after initFirewall has installed the baseline external-chain
	// accept rules. start() is idempotent across Init/Close/Init cycles.
	m.extMonitor.start()

	return nil
}

// reconcileExternalChains re-applies passthrough accept rules to external
// filter chains for both IPv4 and IPv6 routers. Called by the monitor when
// tables or chains appear (e.g. after firewalld reloads).
func (m *Manager) reconcileExternalChains() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error
	if m.router != nil {
		if err := m.router.acceptExternalChainsRules(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("v4: %w", err))
		}
	}
	if m.hasIPv6() {
		if err := m.router6.acceptExternalChainsRules(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("v6: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (m *Manager) initFirewall() (err error) {
	workTable, err := m.createWorkTable()
	if err != nil {
		return fmt.Errorf("create work table: %w", err)
	}

	defer func() {
		if err != nil {
			m.rollbackInit()
		}
	}()

	if err := m.router.init(workTable); err != nil {
		return fmt.Errorf("router init: %w", err)
	}

	if err := m.aclManager.init(workTable); err != nil {
		return fmt.Errorf("acl manager init: %w", err)
	}

	if m.hasIPv6() {
		if err := m.initIPv6(); err != nil {
			// Peer has a v6 address: v6 firewall MUST work or we risk fail-open.
			return fmt.Errorf("init IPv6 firewall (required because peer has IPv6 address): %w", err)
		}
	}

	if err := m.initNoTrackChains(workTable); err != nil {
		log.Warnf("raw priority chains not available, notrack rules will be disabled: %v", err)
	}

	return nil
}

// persistState saves the current interface state for potential recreation on restart.
// Unlike iptables, which requires tracking individual rules, nftables maintains
// a known state (our netbird table plus a few static rules). This allows for easy
// cleanup using Close() without needing to store specific rules.
func (m *Manager) persistState(stateManager *statemanager.Manager) {
	stateManager.RegisterState(&ShutdownState{})

	if err := stateManager.UpdateState(&ShutdownState{
		InterfaceState: &InterfaceState{
			NameStr:   m.wgIface.Name(),
			WGAddress: m.wgIface.Address(),
			MTU:       m.router.mtu,
		},
	}); err != nil {
		log.Errorf("failed to update state: %v", err)
	}

	go func() {
		if err := stateManager.PersistState(context.Background()); err != nil {
			log.Errorf("failed to persist state: %v", err)
		}
	}()
}

// rollbackInit performs best-effort cleanup of already-initialized state when Init fails partway through.
func (m *Manager) rollbackInit() {
	if err := m.router.Reset(); err != nil {
		log.Warnf("rollback router: %v", err)
	}
	if m.hasIPv6() {
		if err := m.router6.Reset(); err != nil {
			log.Warnf("rollback v6 router: %v", err)
		}
	}
	if err := m.cleanupNetbirdTables(); err != nil {
		log.Warnf("cleanup tables: %v", err)
	}
	if err := m.rConn.Flush(); err != nil {
		log.Warnf("flush: %v", err)
	}
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

	if ip.To4() != nil {
		return m.aclManager.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
	}

	if !m.hasIPv6() {
		return nil, fmt.Errorf("add peer filtering for %s: %w", ip, firewall.ErrIPv6NotInitialized)
	}
	return m.aclManager6.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
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

	if isIPv6RouteRule(sources, destination) {
		if !m.hasIPv6() {
			return nil, fmt.Errorf("add route filtering: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.AddRouteFiltering(id, sources, destination, proto, sPort, dPort, action)
	}

	return m.router.AddRouteFiltering(id, sources, destination, proto, sPort, dPort, action)
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.hasIPv6() && isIPv6Rule(rule) {
		return m.aclManager6.DeletePeerRule(rule)
	}
	return m.aclManager.DeletePeerRule(rule)
}

func isIPv6Rule(rule firewall.Rule) bool {
	r, ok := rule.(*Rule)
	return ok && r.nftRule != nil && r.nftRule.Table != nil && r.nftRule.Table.Family == nftables.TableFamilyIPv6
}

// isIPv6RouteRule determines whether a route rule belongs to the v6 table.
// For static routes, the destination prefix determines the family. For dynamic
// routes (DomainSet), the sources determine the family since management
// duplicates dynamic rules per family.
func isIPv6RouteRule(sources []netip.Prefix, destination firewall.Network) bool {
	if destination.IsPrefix() {
		return destination.Prefix.Addr().Is6()
	}
	return len(sources) > 0 && sources[0].Addr().Is6()
}

// DeleteRouteRule deletes a routing rule. Route rules live in exactly one
// router; the cached maps are normally authoritative, so the kernel is only
// consulted when neither map knows about the rule.
func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	id := rule.ID()
	r, err := m.routerForRuleID(id, (*router).hasRule)
	if err != nil {
		return err
	}
	return r.DeleteRouteRule(rule)
}

// routerForRuleID picks the router holding the rule with the given id, using
// the supplied lookup. If the cached maps disagree (or both miss), it refreshes
// from the kernel once and re-checks before falling back to the v4 router.
func (m *Manager) routerForRuleID(id string, has func(*router, string) bool) (*router, error) {
	if has(m.router, id) {
		return m.router, nil
	}
	if m.hasIPv6() && has(m.router6, id) {
		return m.router6, nil
	}
	if !m.hasIPv6() {
		return m.router, nil
	}
	if err := m.router.refreshRulesMap(); err != nil {
		return nil, fmt.Errorf("refresh v4 rules: %w", err)
	}
	if err := m.router6.refreshRulesMap(); err != nil {
		return nil, fmt.Errorf("refresh v6 rules: %w", err)
	}
	if has(m.router6, id) && !has(m.router, id) {
		return m.router6, nil
	}
	return m.router, nil
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

	if pair.Destination.IsPrefix() && pair.Destination.Prefix.Addr().Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("add NAT rule: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.AddNatRule(pair)
	}

	if err := m.router.AddNatRule(pair); err != nil {
		return err
	}

	// Dynamic routes need NAT in both tables since resolved IPs can be
	// either v4 or v6. This covers both DomainSet (modern) and the legacy
	// wildcard 0.0.0.0/0 destination where the client resolves DNS.
	// On v6 failure we keep the v4 NAT rule rather than rolling back: half
	// connectivity is better than none, and RemoveNatRule is content-keyed
	// so the eventual cleanup still works.
	if m.hasIPv6() && pair.Dynamic {
		v6Pair := firewall.ToV6NatPair(pair)
		if err := m.router6.AddNatRule(v6Pair); err != nil {
			return fmt.Errorf("add v6 NAT rule: %w", err)
		}
	}

	return nil
}

func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if pair.Destination.IsPrefix() && pair.Destination.Prefix.Addr().Is6() {
		if !m.hasIPv6() {
			return nil
		}
		return m.router6.RemoveNatRule(pair)
	}

	var merr *multierror.Error

	if err := m.router.RemoveNatRule(pair); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove v4 NAT rule: %w", err))
	}

	if m.hasIPv6() && pair.Dynamic {
		v6Pair := firewall.ToV6NatPair(pair)
		if err := m.router6.RemoveNatRule(v6Pair); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove v6 NAT rule: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// AllowNetbird allows netbird interface traffic.
// This is called when USPFilter wraps the native firewall, adding blanket accept
// rules so that packet filtering is handled in userspace instead of by netfilter.
//
// TODO: In USP mode this only adds ACCEPT to the netbird table's own chains,
// which doesn't override DROP rules in external tables (e.g. firewalld).
// Should add passthrough rules to external chains (like the native mode router's
// addExternalChainsRules does) for both the netbird table family and inet tables.
// The netbird table itself is fine (routing chains already exist there), but
// non-netbird tables with INPUT/FORWARD hooks can still DROP our WG traffic.
func (m *Manager) AllowNetbird() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.aclManager.createDefaultAllowRules(); err != nil {
		return fmt.Errorf("create default allow rules: %w", err)
	}
	if m.hasIPv6() {
		if err := m.aclManager6.createDefaultAllowRules(); err != nil {
			return fmt.Errorf("create v6 default allow rules: %w", err)
		}
	}
	if err := m.rConn.Flush(); err != nil {
		return fmt.Errorf("flush allow input netbird rules: %w", err)
	}

	if err := firewalld.TrustInterface(m.wgIface.Name()); err != nil {
		log.Warnf("failed to trust interface in firewalld: %v", err)
	}

	return nil
}

// SetLegacyManagement sets the route manager to use legacy management
func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	if err := firewall.SetLegacyManagement(m.router, isLegacy); err != nil {
		return err
	}
	if m.hasIPv6() {
		return firewall.SetLegacyManagement(m.router6, isLegacy)
	}
	return nil
}

// Close closes the firewall manager
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.extMonitor.stop()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error

	if err := m.router.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset router: %v", err))
	}

	if m.hasIPv6() {
		if err := m.router6.Reset(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reset v6 router: %v", err))
		}
	}

	if err := m.cleanupNetbirdTables(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("cleanup netbird tables: %v", err))
	}

	if err := m.rConn.Flush(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf(flushError, err))
	}

	if err := stateManager.DeleteState(&ShutdownState{}); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("delete state: %v", err))
	}

	return nberrors.FormatErrorOrNil(merr)
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

	if m.hasIPv6() {
		if err := m.aclManager6.Flush(); err != nil {
			return fmt.Errorf("flush v6 acl: %w", err)
		}
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

	if rule.TranslatedAddress.Is6() {
		if !m.hasIPv6() {
			return nil, fmt.Errorf("add DNAT rule: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.AddDNATRule(rule)
	}
	return m.router.AddDNATRule(rule)
}

// DeleteDNATRule deletes a DNAT rule
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	r, err := m.routerForRuleID(rule.ID(), (*router).hasDNATRule)
	if err != nil {
		return err
	}
	return r.DeleteDNATRule(rule)
}

// UpdateSet updates the set with the given prefixes
func (m *Manager) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var v4Prefixes, v6Prefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is6() {
			v6Prefixes = append(v6Prefixes, p)
		} else {
			v4Prefixes = append(v4Prefixes, p)
		}
	}

	if err := m.router.UpdateSet(set, v4Prefixes); err != nil {
		return err
	}

	if m.hasIPv6() && len(v6Prefixes) > 0 {
		if err := m.router6.UpdateSet(set, v6Prefixes); err != nil {
			return fmt.Errorf("update v6 set: %w", err)
		}
	}

	return nil
}

// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services.
func (m *Manager) AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("add inbound DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.AddInboundDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.router.AddInboundDNAT(localAddr, protocol, originalPort, translatedPort)
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (m *Manager) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("remove inbound DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.RemoveInboundDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.router.RemoveInboundDNAT(localAddr, protocol, originalPort, translatedPort)
}

// AddOutputDNAT adds an OUTPUT chain DNAT rule for locally-generated traffic.
func (m *Manager) AddOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("add output DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.AddOutputDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.router.AddOutputDNAT(localAddr, protocol, originalPort, translatedPort)
}

// RemoveOutputDNAT removes an OUTPUT chain DNAT rule.
func (m *Manager) RemoveOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("remove output DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.router6.RemoveOutputDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.router.RemoveOutputDNAT(localAddr, protocol, originalPort, translatedPort)
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
	return m.createWorkTableFamily(nftables.TableFamilyIPv4)
}

func (m *Manager) createWorkTableFamily(family nftables.TableFamily) (*nftables.Table, error) {
	tables, err := m.rConn.ListTablesOfFamily(family)
	if err != nil {
		return nil, fmt.Errorf("list of tables: %w", err)
	}

	tableName := getTableName()
	for _, t := range tables {
		if t.Name == tableName {
			m.rConn.DelTable(t)
		}
	}

	table := m.rConn.AddTable(&nftables.Table{Name: tableName, Family: family})
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
