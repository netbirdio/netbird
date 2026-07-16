package iptables

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Manager of iptables firewall. Per-family state (peer ACLs, route
// ACLs, NAT, DNAT, MSS clamping) lives on family; Manager dispatches
// by family and provides the public firewall.Manager surface.
type Manager struct {
	mutex sync.Mutex

	wgIface iFaceMapper

	ipv4Client   *iptables.IPTables
	family4      *family
	rawSupported bool

	// IPv6 counterparts, nil when no v6 overlay
	ipv6Client *iptables.IPTables
	family6    *family
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() wgaddr.Address
}

// Create iptables firewall manager
func Create(wgIface iFaceMapper, mtu uint16) (*Manager, error) {
	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("init iptables: %w", err)
	}

	m := &Manager{
		wgIface:    wgIface,
		ipv4Client: iptablesClient,
	}

	m.family4, err = newFamily(iptablesClient, wgIface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create family: %w", err)
	}

	if wgIface.Address().HasIPv6() {
		if err := m.createIPv6Components(wgIface, mtu); err != nil {
			return nil, fmt.Errorf("create IPv6 firewall: %w", err)
		}
	}

	return m, nil
}

func (m *Manager) createIPv6Components(wgIface iFaceMapper, mtu uint16) error {
	ip6Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return fmt.Errorf("init ip6tables: %w", err)
	}

	family6, err := newFamily(ip6Client, wgIface, mtu)
	if err != nil {
		return fmt.Errorf("create v6 family: %w", err)
	}

	// Share the same IP forwarding state with the v4 family, since
	// EnableIPForwarding controls both v4 and v6 sysctls.
	family6.ipFwdState = m.family4.ipFwdState

	m.ipv6Client = ip6Client
	m.family6 = family6

	return nil
}

func (m *Manager) hasIPv6() bool {
	return m.ipv6Client != nil
}

func (m *Manager) Init(stateManager *statemanager.Manager) error {
	state := &ShutdownState{
		InterfaceState: &InterfaceState{
			NameStr:   m.wgIface.Name(),
			WGAddress: m.wgIface.Address(),
			MTU:       m.family4.mtu,
		},
	}
	stateManager.RegisterState(state)
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update state: %v", err)
	}

	if err := m.initChains(stateManager); err != nil {
		return err
	}

	if err := m.initNoTrackChain(); err != nil {
		log.Warnf("raw table not available, notrack rules will be disabled: %v", err)
	}

	// Trust after all fatal init steps so a later failure doesn't leave the
	// interface in firewalld's trusted zone without a corresponding Close.
	if err := firewalld.TrustInterface(m.wgIface.Name()); err != nil {
		log.Warnf("failed to trust interface in firewalld: %v", err)
	}

	// persist early to ensure cleanup of chains
	go func() {
		if err := stateManager.PersistState(context.Background()); err != nil {
			log.Errorf("failed to persist state: %v", err)
		}
	}()

	return nil
}

// initChains initializes the per-family firewall state for both
// address families, rolling back on failure.
func (m *Manager) initChains(stateManager *statemanager.Manager) error {
	type initStep struct {
		name string
		r    *family
	}

	steps := []initStep{{"v4", m.family4}}
	if m.hasIPv6() {
		steps = append(steps, initStep{"v6", m.family6})
	}

	var initialized []initStep
	for _, s := range steps {
		if err := s.r.init(stateManager); err != nil {
			for i := len(initialized) - 1; i >= 0; i-- {
				if rerr := initialized[i].r.Reset(); rerr != nil {
					log.Warnf("rollback %s: %v", initialized[i].name, rerr)
				}
			}
			return fmt.Errorf("%s init: %w", s.name, err)
		}
		initialized = append(initialized, s)
	}
	return nil
}

// AddFilterRule installs a packet-filtering rule. See firewall.Manager
// docs for destination semantics. Sources are a single address family;
// the rule is dispatched to the matching v4 / v6 backend.
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

// DeleteFilterRule removes a rule previously added via AddFilterRule.
// The rule is looked up by id in each family's filter cache.
func (m *Manager) DeleteFilterRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	id := rule.ID()
	if m.family4.hasRule(id) {
		return m.family4.DeleteFilterRule(rule)
	}
	if m.hasIPv6() && m.family6.hasRule(id) {
		return m.family6.DeleteFilterRule(rule)
	}
	log.Debugf("filter rule %s not found in any family", id)
	return nil
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

func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := firewall.SetLegacyManagement(m.family4, isLegacy); err != nil {
		return err
	}
	if m.hasIPv6() {
		return firewall.SetLegacyManagement(m.family6, isLegacy)
	}
	return nil
}

// Reset firewall to the default state
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error

	if err := m.cleanupNoTrackChain(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("cleanup notrack chain: %w", err))
	}

	if m.hasIPv6() {
		if err := m.family6.Reset(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reset v6 family: %w", err))
		}
	}

	if err := m.family4.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset family: %w", err))
	}

	// Appending to merr intentionally blocks DeleteState below so ShutdownState
	// stays persisted and the crash-recovery path retries firewalld cleanup.
	if err := firewalld.UntrustInterface(m.wgIface.Name()); err != nil {
		merr = multierror.Append(merr, err)
	}

	// attempt to delete state only if all other operations succeeded
	if merr == nil {
		if err := stateManager.DeleteState(&ShutdownState{}); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete state: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

// SetLogLevel sets the log level for the firewall manager
func (m *Manager) SetLogLevel(log.Level) {
	// not supported
}

func (m *Manager) EnableRouting() error {
	if err := m.family4.ipFwdState.RequestForwarding(); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}
	return nil
}

func (m *Manager) DisableRouting() error {
	if err := m.family4.ipFwdState.ReleaseForwarding(); err != nil {
		return fmt.Errorf("disable IP forwarding: %w", err)
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
		return m.family6.AddDNATRule(rule)
	}
	return m.family4.AddDNATRule(rule)
}

// DeleteDNATRule deletes a DNAT rule
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.hasIPv6() && !m.family4.hasDNATRule(rule.ID()) {
		return m.family6.DeleteDNATRule(rule)
	}
	return m.family4.DeleteDNATRule(rule)
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

const (
	chainNameRaw = "NETBIRD-RAW"
	chainOutput  = "OUTPUT"
	tableRaw     = "raw"
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

	if !m.rawSupported {
		return fmt.Errorf("raw table not available")
	}

	wgPortStr := fmt.Sprintf("%d", wgPort)
	proxyPortStr := fmt.Sprintf("%d", proxyPort)

	// Egress rules: match outgoing loopback UDP packets
	outputRuleSport := []string{"-o", "lo", "-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "udp", "--sport", wgPortStr, "-j", "NOTRACK"}
	if err := m.ipv4Client.AppendUnique(tableRaw, chainNameRaw, outputRuleSport...); err != nil {
		return fmt.Errorf("add output sport notrack rule: %w", err)
	}

	outputRuleDport := []string{"-o", "lo", "-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "udp", "--dport", wgPortStr, "-j", "NOTRACK"}
	if err := m.ipv4Client.AppendUnique(tableRaw, chainNameRaw, outputRuleDport...); err != nil {
		return fmt.Errorf("add output dport notrack rule: %w", err)
	}

	// Ingress rules: match incoming loopback UDP packets
	preroutingRuleWg := []string{"-i", "lo", "-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "udp", "--dport", wgPortStr, "-j", "NOTRACK"}
	if err := m.ipv4Client.AppendUnique(tableRaw, chainNameRaw, preroutingRuleWg...); err != nil {
		return fmt.Errorf("add prerouting wg notrack rule: %w", err)
	}

	preroutingRuleProxy := []string{"-i", "lo", "-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "udp", "--dport", proxyPortStr, "-j", "NOTRACK"}
	if err := m.ipv4Client.AppendUnique(tableRaw, chainNameRaw, preroutingRuleProxy...); err != nil {
		return fmt.Errorf("add prerouting proxy notrack rule: %w", err)
	}

	log.Debugf("set up ebpf proxy notrack rules for ports %d,%d", proxyPort, wgPort)
	return nil
}

func (m *Manager) initNoTrackChain() error {
	if err := m.cleanupNoTrackChain(); err != nil {
		log.Debugf("cleanup notrack chain: %v", err)
	}

	if err := m.ipv4Client.NewChain(tableRaw, chainNameRaw); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	jumpRule := []string{"-j", chainNameRaw}

	if err := m.ipv4Client.InsertUnique(tableRaw, chainOutput, 1, jumpRule...); err != nil {
		if delErr := m.ipv4Client.DeleteChain(tableRaw, chainNameRaw); delErr != nil {
			log.Debugf("delete orphan chain: %v", delErr)
		}
		return fmt.Errorf("add output jump rule: %w", err)
	}

	if err := m.ipv4Client.InsertUnique(tableRaw, chainPrerouting, 1, jumpRule...); err != nil {
		if delErr := m.ipv4Client.DeleteIfExists(tableRaw, chainOutput, jumpRule...); delErr != nil {
			log.Debugf("delete output jump rule: %v", delErr)
		}
		if delErr := m.ipv4Client.DeleteChain(tableRaw, chainNameRaw); delErr != nil {
			log.Debugf("delete orphan chain: %v", delErr)
		}
		return fmt.Errorf("add prerouting jump rule: %w", err)
	}

	m.rawSupported = true
	return nil
}

func (m *Manager) cleanupNoTrackChain() error {
	exists, err := m.ipv4Client.ChainExists(tableRaw, chainNameRaw)
	if err != nil {
		if !m.rawSupported {
			return nil
		}
		return fmt.Errorf("check chain exists: %w", err)
	}
	if !exists {
		return nil
	}

	jumpRule := []string{"-j", chainNameRaw}

	if err := m.ipv4Client.DeleteIfExists(tableRaw, chainOutput, jumpRule...); err != nil {
		return fmt.Errorf("remove output jump rule: %w", err)
	}

	if err := m.ipv4Client.DeleteIfExists(tableRaw, chainPrerouting, jumpRule...); err != nil {
		return fmt.Errorf("remove prerouting jump rule: %w", err)
	}

	if err := m.ipv4Client.ClearAndDeleteChain(tableRaw, chainNameRaw); err != nil {
		return fmt.Errorf("clear and delete chain: %w", err)
	}

	m.rawSupported = false
	return nil
}

func getConntrackEstablished() []string {
	return []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
}

// isIPv6Rule reports whether the rule belongs to the IPv6 family, from
// the destination prefix when set, otherwise from the (single-family)
// sources.
func isIPv6Rule(sources []netip.Prefix, destination firewall.Network) bool {
	if destination.IsPrefix() {
		return destination.Prefix.Addr().Is6()
	}
	return len(sources) > 0 && sources[0].Addr().Is6()
}
