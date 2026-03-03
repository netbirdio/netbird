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
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	wgIface iFaceMapper

	ipv4Client *iptables.IPTables
	aclMgr     *aclManager
	router     *router
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() wgaddr.Address
	IsUserspaceBind() bool
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

	return m, nil
}

func (m *Manager) Init(stateManager *statemanager.Manager) error {
	state := &ShutdownState{
		InterfaceState: &InterfaceState{
			NameStr:       m.wgIface.Name(),
			WGAddress:     m.wgIface.Address(),
			UserspaceBind: m.wgIface.IsUserspaceBind(),
			MTU:           m.router.mtu,
		},
	}
	stateManager.RegisterState(state)
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update state: %v", err)
	}

	if err := m.router.init(stateManager); err != nil {
		return fmt.Errorf("router init: %w", err)
	}

	if err := m.aclMgr.init(stateManager); err != nil {
		// TODO: cleanup router
		return fmt.Errorf("acl manager init: %w", err)
	}

	if err := m.initNoTrackChain(); err != nil {
		return fmt.Errorf("init notrack chain: %w", err)
	}

	// persist early to ensure cleanup of chains
	go func() {
		if err := stateManager.PersistState(context.Background()); err != nil {
			log.Errorf("failed to persist state: %v", err)
		}
	}()

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

	return m.aclMgr.AddPeerFiltering(id, ip, proto, sPort, dPort, action, ipsetName)
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

	return m.aclMgr.DeletePeerRule(rule)
}

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

func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	return firewall.SetLegacyManagement(m.router, isLegacy)
}

// Reset firewall to the default state
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var merr *multierror.Error

	if err := m.cleanupNoTrackChain(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("cleanup notrack chain: %w", err))
	}

	if err := m.aclMgr.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset acl manager: %w", err))
	}
	if err := m.router.Reset(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset router: %w", err))
	}

	// attempt to delete state only if all other operations succeeded
	if merr == nil {
		if err := stateManager.DeleteState(&ShutdownState{}); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete state: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if !m.wgIface.IsUserspaceBind() {
		return nil
	}

	_, err := m.AddPeerFiltering(
		nil,
		net.IP{0, 0, 0, 0},
		firewall.ProtocolALL,
		nil,
		nil,
		firewall.ActionAccept,
		"",
	)
	if err != nil {
		return fmt.Errorf("allow netbird interface traffic: %w", err)
	}
	return nil
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

	return nil
}

func (m *Manager) cleanupNoTrackChain() error {
	exists, err := m.ipv4Client.ChainExists(tableRaw, chainNameRaw)
	if err != nil {
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

	return nil
}

func getConntrackEstablished() []string {
	return []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
}
