package nftables

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
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

// probeTablePrefix starts the name of the throwaway table probeIPv6Filtering creates.
const probeTablePrefix = "netbird-ipv6-probe-"

// hostHasIPv6 is a variable so tests can change what the host looks like.
var hostHasIPv6 = firewall.HostHasIPv6

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() wgaddr.Address
}

// Manager of nftables firewall. Per-family state (peer ACLs, route
// ACLs, NAT, DNAT, MSS clamping) lives on family; Manager dispatches
// by family and provides the public firewall.Manager surface.
type Manager struct {
	mutex   sync.Mutex
	rConn   *nftables.Conn
	wgIface iFaceMapper

	family4 *family
	// IPv6 counterpart. It exists when the interface has an IPv6 overlay address, and also
	// when it has none but the host has IPv6, so IPv6 arriving on the interface is dropped
	// instead of being left to the host's rules. nil when the host has no IPv6, or when
	// NB_ALLOW_UNFILTERED_IPV6 leaves it to the host's rules.
	family6 *family
	// v6Overlay is true when the interface has an IPv6 overlay address, and
	// IPv6 rules, NAT and forwarding are handled.
	v6Overlay bool

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

	m.family4 = newFamily(workTable, wgIface, mtu)

	m.v6Overlay = wgIface.Address().HasIPv6()
	switch {
	case m.v6Overlay:
		m.createIPv6Components(tableName, wgIface, mtu)
	case !hostHasIPv6(wgIface.Name()):
		log.Debugf("host has no IPv6, no IPv6 firewall for interface %s", wgIface.Name())
	case firewall.AllowUnfilteredIPv6():
		log.Warnf("%s is set: IPv6 arriving on interface %s is left to the host's rules", firewall.EnvAllowUnfilteredIPv6, wgIface.Name())
	default:
		if err := probeIPv6Filtering(); err != nil {
			// Nothing can filter IPv6 here, and failing would only drop the native firewall.
			log.Warnf("IPv6 arriving on interface %s is not filtered: %v", wgIface.Name(), err)
			break
		}
		log.Infof("interface %s has no IPv6 overlay address, dropping IPv6 arriving on it", wgIface.Name())
		m.createIPv6Components(tableName, wgIface, mtu)
	}

	m.extMonitor = newExternalChainMonitor(m)

	return m, nil
}

// probeIPv6Filtering checks that this kernel can hold an IPv6 table with a filter chain on the
// input hook and a NAT chain, by creating and removing a throwaway one. The table has a name of its own, so
// concurrent probes and leftovers of an interrupted one do not interfere.
func probeIPv6Filtering() error {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate probe table name: %w", err)
	}

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Name:   probeTablePrefix + hex.EncodeToString(suffix),
		Family: nftables.TableFamilyIPv6,
	})
	conn.AddChain(&nftables.Chain{
		Name:     chainNameInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	// The IPv6 family also sets up NAT chains.
	conn.AddChain(&nftables.Chain{
		Name:     "nat-postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("create IPv6 probe table: %w", err)
	}

	// Creating the table showed the kernel supports it. A failed removal, for example
	// because a crash cleanup already swept the table, must not turn into an unfiltered
	// IPv6 path, and a leftover is removed by the next cleanup.
	conn.DelTable(table)
	if err := conn.Flush(); err != nil {
		log.Debugf("delete IPv6 probe table: %v", err)
	}
	return nil
}

func (m *Manager) createIPv6Components(tableName string, wgIface iFaceMapper, mtu uint16) {
	workTable6 := &nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv6}

	m.family6 = newFamily(workTable6, wgIface, mtu)
	m.family6.denyOnly = !m.v6Overlay

	// Share the per-family forwarding refcounter with the v4 family so a v4
	// rule and a v6 rule against the same state machine cooperate cleanly.
	m.family6.ipFwdState = m.family4.ipFwdState
}

// hasIPv6 reports whether the interface has an IPv6 overlay address, that is whether IPv6
// rules, NAT and forwarding apply. Setup and teardown of the IPv6 family use hasV6Family.
func (m *Manager) hasIPv6() bool {
	return m.v6Overlay && m.family6 != nil
}

// hasV6Family reports whether the IPv6 family exists and has to be set up, flushed and
// removed, whether it carries IPv6 rules or only the default deny.
func (m *Manager) hasV6Family() bool {
	return m.family6 != nil
}

func (m *Manager) initIPv6() error {
	workTable6, err := m.createWorkTableFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return fmt.Errorf("create v6 work table: %w", err)
	}

	if err := m.family6.init(workTable6); err != nil {
		return fmt.Errorf("v6 family init: %w", err)
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
// tables or chains appear (e.g. after firewalld reloads). Kernel routing opens
// both INPUT and FORWARD.
func (m *Manager) reconcileExternalChains() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error
	if m.family4 != nil {
		if err := m.family4.acceptExternalChainsRules(true); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("v4: %w", err))
		}
	}
	if m.hasV6Family() {
		if err := m.family6.acceptExternalChainsRules(true); err != nil {
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

	if err := m.family4.init(workTable); err != nil {
		return fmt.Errorf("family init: %w", err)
	}

	if m.hasV6Family() {
		if err := m.initIPv6(); err != nil {
			// IPv6 is reachable on the interface: the v6 firewall MUST work or we risk fail-open.
			return fmt.Errorf("init IPv6 firewall (required because the host has IPv6): %w", err)
		}
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
			MTU:       m.family4.mtu,
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
	if err := m.family4.Reset(); err != nil {
		log.Warnf("rollback family: %v", err)
	}
	if m.hasV6Family() {
		if err := m.family6.Reset(); err != nil {
			log.Warnf("rollback v6 family: %v", err)
		}
	}
	if err := m.cleanupNetbirdTables(); err != nil {
		log.Warnf("cleanup tables: %v", err)
	}
	if err := m.rConn.Flush(); err != nil {
		log.Warnf("flush: %v", err)
	}
}

// AddFilterRule installs a packet-filtering rule.
//
// Destination semantics: zero Network → input chain (peer ACL);
// set Network → forward chain (route ACL).
//
// Sources are a single address family; the rule is dispatched to the
// matching per-family backend.
func (m *Manager) AddFilterRule(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	if len(sources) == 0 {
		return nil, firewall.ErrNoSources
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	fam := m.family4
	if isIPv6Rule(sources, destination) {
		if !m.hasIPv6() {
			return nil, fmt.Errorf("add filtering: %w", firewall.ErrIPv6NotInitialized)
		}
		fam = m.family6
	}
	return fam.AddFilterRule(id, sources, destination, proto, sPort, dPort, action)
}

// DeleteFilterRule removes a filtering rule. The owning family is found
// by id in the in-memory filter maps, which are the only tracking for
// filter rules. family.DeleteFilterRule is idempotent when the id is
// absent.
func (m *Manager) DeleteFilterRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	fam, err := m.familyForRuleID(rule.ID(), (*family).hasRule)
	if err != nil {
		return err
	}
	return fam.DeleteFilterRule(rule)
}

// familyForRuleID picks the family holding the rule with the given id, using
// the supplied lookup, and falls back to the v4 family on a miss.
func (m *Manager) familyForRuleID(id firewall.RuleID, has func(*family, firewall.RuleID) bool) (*family, error) {
	if has(m.family4, id) {
		return m.family4, nil
	}
	if !m.hasIPv6() {
		return m.family4, nil
	}
	if has(m.family6, id) {
		return m.family6, nil
	}
	return m.family4, nil
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
		return m.family6.AddNatRule(pair)
	}

	if err := m.family4.AddNatRule(pair); err != nil {
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
		if err := m.family6.AddNatRule(v6Pair); err != nil {
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
		return m.family6.RemoveNatRule(pair)
	}

	var merr *multierror.Error

	if err := m.family4.RemoveNatRule(pair); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove v4 NAT rule: %w", err))
	}

	if m.hasIPv6() && pair.Dynamic {
		v6Pair := firewall.ToV6NatPair(pair)
		if err := m.family6.RemoveNatRule(v6Pair); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove v6 NAT rule: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// SetLegacyManagement sets the route manager to use legacy management
func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	if err := firewall.SetLegacyManagement(m.family4, isLegacy); err != nil {
		return err
	}
	if m.hasIPv6() {
		return firewall.SetLegacyManagement(m.family6, isLegacy)
	}
	return nil
}

// Close closes the firewall manager
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.extMonitor.stop()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error

	if err := m.family4.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset family: %w", err))
	}

	if m.hasV6Family() {
		if err := m.family6.Reset(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reset v6 family: %w", err))
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
		// Probe tables only outlive their probe when the process died in between.
		isProbe := t.Family == nftables.TableFamilyIPv6 && strings.HasPrefix(t.Name, probeTablePrefix)
		if t.Name == tableName || isProbe {
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
	// v6 only when the overlay actually has v6.
	return m.family4.ipFwdState.RequestRouting(m.hasIPv6())
}

func (m *Manager) DisableRouting() error {
	return m.family4.ipFwdState.ReleaseRouting()
}

// Flush rule/chain/set operations from the buffer
//
// Method also get all rules after flush and refreshes handle values in the rulesets
// todo review this method usage
func (m *Manager) Flush() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.family4.Flush(); err != nil {
		return err
	}

	if m.hasV6Family() {
		if err := m.family6.Flush(); err != nil {
			return fmt.Errorf("flush v6 family: %w", err)
		}
	}

	return nil
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

	if err := m.family4.UpdateSet(set, v4Prefixes); err != nil {
		return err
	}

	if m.hasIPv6() && len(v6Prefixes) > 0 {
		if err := m.family6.UpdateSet(set, v6Prefixes); err != nil {
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
		return m.family6.AddInboundDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.family4.AddInboundDNAT(localAddr, protocol, originalPort, translatedPort)
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (m *Manager) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("remove inbound DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.family6.RemoveInboundDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.family4.RemoveInboundDNAT(localAddr, protocol, originalPort, translatedPort)
}

// AddOutputDNAT adds an OUTPUT chain DNAT rule for locally-generated traffic.
func (m *Manager) AddOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("add output DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.family6.AddOutputDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.family4.AddOutputDNAT(localAddr, protocol, originalPort, translatedPort)
}

// RemoveOutputDNAT removes an OUTPUT chain DNAT rule.
func (m *Manager) RemoveOutputDNAT(localAddr netip.Addr, protocol firewall.Protocol, originalPort, translatedPort uint16) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if localAddr.Is6() {
		if !m.hasIPv6() {
			return fmt.Errorf("remove output DNAT: %w", firewall.ErrIPv6NotInitialized)
		}
		return m.family6.RemoveOutputDNAT(localAddr, protocol, originalPort, translatedPort)
	}
	return m.family4.RemoveOutputDNAT(localAddr, protocol, originalPort, translatedPort)
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

// isIPv6Rule reports whether the rule belongs to the v6 table. For a
// prefix destination the destination family decides; otherwise the
// (single-family) sources do, since management duplicates rules per
// family.
func isIPv6Rule(sources []netip.Prefix, destination firewall.Network) bool {
	if destination.IsPrefix() {
		return destination.Prefix.Addr().Is6()
	}
	return len(sources) > 0 && sources[0].Addr().Is6()
}
