package iptables

import (
	"context"
	"fmt"
	"net"
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

type resetter interface {
	Reset() error
}

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	wgIface iFaceMapper

	ipv4Client   *iptables.IPTables
	aclMgr       *aclManager
	router       *router
	rawSupported bool

	// IPv6 counterparts, nil when no v6 overlay
	ipv6Client *iptables.IPTables
	aclMgr6    *aclManager
	router6    *router
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

	m.router, err = newRouter(iptablesClient, wgIface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	m.aclMgr, err = newAclManager(iptablesClient, wgIface)
	if err != nil {
		return nil, fmt.Errorf("create acl manager: %w", err)
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
	m.ipv6Client = ip6Client

	m.router6, err = newRouter(ip6Client, wgIface, mtu)
	if err != nil {
		return fmt.Errorf("create v6 router: %w", err)
	}

	// Share the same IP forwarding state with the v4 router, since
	// EnableIPForwarding controls both v4 and v6 sysctls.
	m.router6.ipFwdState = m.router.ipFwdState

	m.aclMgr6, err = newAclManager(ip6Client, wgIface)
	if err != nil {
		return fmt.Errorf("create v6 acl manager: %w", err)
	}

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
			MTU:       m.router.mtu,
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

// initChains initializes router and ACL chains for both address families,
// rolling back on failure.
func (m *Manager) initChains(stateManager *statemanager.Manager) error {
	type initStep struct {
		name string
		init func(*statemanager.Manager) error
		mgr  resetter
	}

	steps := []initStep{
		{"router", m.router.init, m.router},
		{"acl manager", m.aclMgr.init, m.aclMgr},
	}
	if m.hasIPv6() {
		steps = append(steps,
			initStep{"v6 router", m.router6.init, m.router6},
			initStep{"v6 acl manager", m.aclMgr6.init, m.aclMgr6},
		)
	}

	var initialized []initStep
	for _, s := range steps {
		if err := s.init(stateManager); err != nil {
			for i := len(initialized) - 1; i >= 0; i-- {
				if rerr := initialized[i].mgr.Reset(); rerr != nil {
					log.Warnf("rollback %s: %v", initialized[i].name, rerr)
				}
			}
			return fmt.Errorf("%s init: %w", s.name, err)
		}
		initialized = append(initialized, s)
	}
	return nil
}

// AddPeerFiltering adds a rule to the firewall
//
// Comment will be ignored because some system this feature is not supported
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
		return m.aclMgr.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
	}
	if !m.hasIPv6() {
		return nil, fmt.Errorf("add peer filtering for %s: %w", ip, firewall.ErrIPv6NotInitialized)
	}
	return m.aclMgr6.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
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

func isIPv6RouteRule(sources []netip.Prefix, destination firewall.Network) bool {
	if destination.IsPrefix() {
		return destination.Prefix.Addr().Is6()
	}
	return len(sources) > 0 && sources[0].Addr().Is6()
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.hasIPv6() && isIPv6IptRule(rule) {
		return m.aclMgr6.DeletePeerRule(rule)
	}
	return m.aclMgr.DeletePeerRule(rule)
}

func isIPv6IptRule(rule firewall.Rule) bool {
	r, ok := rule.(*Rule)
	return ok && r.v6
}

// DeleteRouteRule deletes a routing rule.
// Route rules are keyed by content hash. Check v4 first, try v6 if not found.
func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.hasIPv6() && !m.router.hasRule(rule.ID()) {
		return m.router6.DeleteRouteRule(rule)
	}
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

func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	if err := firewall.SetLegacyManagement(m.router, isLegacy); err != nil {
		return err
	}
	if m.hasIPv6() {
		return firewall.SetLegacyManagement(m.router6, isLegacy)
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
		if err := m.aclMgr6.Reset(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reset v6 acl manager: %w", err))
		}
		if err := m.router6.Reset(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reset v6 router: %w", err))
		}
	}

	if err := m.aclMgr.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset acl manager: %w", err))
	}
	if err := m.router.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset router: %w", err))
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

// AllowNetbird allows netbird interface traffic.
// This is called when USPFilter wraps the native firewall, adding blanket accept
// rules so that packet filtering is handled in userspace instead of by netfilter.
func (m *Manager) AllowNetbird() error {
	var merr *multierror.Error
	if _, err := m.AddPeerFiltering(nil, net.IP{0, 0, 0, 0}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept, ""); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("allow netbird v4 interface traffic: %w", err))
	}
	if m.hasIPv6() {
		if _, err := m.AddPeerFiltering(nil, net.IPv6zero, firewall.ProtocolALL, nil, nil, firewall.ActionAccept, ""); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("allow netbird v6 interface traffic: %w", err))
		}
	}

	if err := firewalld.TrustInterface(m.wgIface.Name()); err != nil {
		log.Warnf("failed to trust interface in firewalld: %v", err)
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

	if m.hasIPv6() && !m.router.hasRule(rule.ID()+dnatSuffix) {
		return m.router6.DeleteDNATRule(rule)
	}
	return m.router.DeleteDNATRule(rule)
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
	chainNameRaw = "NETBIRD-RAW"
	chainOUTPUT  = "OUTPUT"
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

	if err := m.ipv4Client.InsertUnique(tableRaw, chainOUTPUT, 1, jumpRule...); err != nil {
		if delErr := m.ipv4Client.DeleteChain(tableRaw, chainNameRaw); delErr != nil {
			log.Debugf("delete orphan chain: %v", delErr)
		}
		return fmt.Errorf("add output jump rule: %w", err)
	}

	if err := m.ipv4Client.InsertUnique(tableRaw, chainPREROUTING, 1, jumpRule...); err != nil {
		if delErr := m.ipv4Client.DeleteIfExists(tableRaw, chainOUTPUT, jumpRule...); delErr != nil {
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

	if err := m.ipv4Client.DeleteIfExists(tableRaw, chainOUTPUT, jumpRule...); err != nil {
		return fmt.Errorf("remove output jump rule: %w", err)
	}

	if err := m.ipv4Client.DeleteIfExists(tableRaw, chainPREROUTING, jumpRule...); err != nil {
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
