package uspfilter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	wgdevice "golang.zx2c4.com/wireguard/device"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/forwarder"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	layerTypeAll = 255

	// ipv4TCPHeaderMinSize represents minimum IPv4 (20) + TCP (20) header size for MSS calculation
	ipv4TCPHeaderMinSize = 40
	// ipv6TCPHeaderMinSize represents minimum IPv6 (40) + TCP (20) header size for MSS calculation
	ipv6TCPHeaderMinSize = 60
)

// serviceKey represents a protocol/port combination for netstack service registry
type serviceKey struct {
	protocol gopacket.LayerType
	port     uint16
}

const (
	// EnvDisableConntrack disables the stateful filter, replies to outbound traffic won't be allowed.
	EnvDisableConntrack = "NB_DISABLE_CONNTRACK"

	// EnvDisableUserspaceRouting disables userspace routing, to-be-routed packets will be dropped.
	EnvDisableUserspaceRouting = "NB_DISABLE_USERSPACE_ROUTING"

	// EnvDisableMSSClamping disables TCP MSS clamping for forwarded traffic.
	EnvDisableMSSClamping = "NB_DISABLE_MSS_CLAMPING"

	// EnvForceUserspaceRouter is a deprecated alias for
	// NB_FORCE_USERSPACE_FIREWALL: the userspace firewall always routes in
	// userspace, so forcing one forces the other. Kept for backward
	// compatibility.
	EnvForceUserspaceRouter = "NB_FORCE_USERSPACE_ROUTER"

	// EnvEnableLocalForwarding enables forwarding of local traffic to the native stack for internal (non-NetBird) interfaces.
	// Default off as it might be security risk because sockets listening on localhost only will become accessible.
	EnvEnableLocalForwarding = "NB_ENABLE_LOCAL_FORWARDING"

	// EnvEnableNetstackLocalForwarding is an alias for EnvEnableLocalForwarding.
	// In netstack mode, it enables forwarding of local traffic to the native stack for all interfaces.
	EnvEnableNetstackLocalForwarding = "NB_ENABLE_NETSTACK_LOCAL_FORWARDING"
)

// errNotSupported is returned by firewall operations that only make sense with
// a kernel firewall (kernel NAT/DNAT, eBPF) and are not implemented in
// userspace mode, where they should not be called.
var errNotSupported = errors.New("not supported with userspace firewall")

// peerRules is the canonical list-based storage for peer ACL rules.
// Drop and accept rules live in separate slices; drop-before-accept
// ordering comes from consulting the deny slice (and its index) before
// the accept one.
type peerRules []*PeerRule

type routeRules []*RouteRule

func (r routeRules) Sort() {
	slices.SortStableFunc(r, func(a, b *RouteRule) int {
		// Deny rules come first
		if a.action == firewall.ActionDrop && b.action != firewall.ActionDrop {
			return -1
		}
		if a.action != firewall.ActionDrop && b.action == firewall.ActionDrop {
			return 1
		}
		return strings.Compare(string(a.id), string(b.id))
	})
}

// peerRuleSpec carries the parameters that define a peer filter rule,
// threaded together through the build path so the builders take a single
// argument instead of a long parameter list.
type peerRuleSpec struct {
	mgmtID  []byte
	sources []netip.Prefix
	ipLayer gopacket.LayerType
	proto   firewall.Protocol
	sPort   *firewall.Port
	dPort   *firewall.Port
	action  firewall.Action
}

// Iface is the network interface the userspace firewall attaches to: the
// methods of the WireGuard device it actually uses.
type Iface interface {
	Name() string
	Address() wgaddr.Address
	SetFilter(device.PacketFilter) error
	GetWGDevice() *wgdevice.Device
}

// InterfaceAllower opens the NetBird interface in the host firewall so it
// doesn't drop traffic the userspace firewall handles, without taking over
// packet filtering. Implementations (nftables, iptables, firewalld, the windows
// netsh rule) are selected per platform and injected into Create; Apply runs at
// creation and Close on teardown.
type InterfaceAllower interface {
	Apply() error
	Close() error
}

// Config holds the dependencies and options for the userspace firewall.
type Config struct {
	// IFace is the overlay interface the filter attaches to.
	IFace Iface
	// InterfaceAllower opens the NetBird interface in foreign kernel filter
	// chains so the kernel doesn't drop traffic the userspace firewall handles.
	// Nil in netstack mode, on non-Linux platforms without a backend, or when
	// neither nftables nor iptables is available. firewalld trust is applied by
	// the manager regardless, since firewalld owns its own chains and we cannot
	// insert into them.
	InterfaceAllower InterfaceAllower
	// DisableServerRoutes indicates whether server routes are disabled.
	DisableServerRoutes bool
	FlowLogger          nftypes.FlowLogger
	MTU                 uint16
}

// Manager userspace firewall manager
type Manager struct {
	decoders     sync.Pool
	wgIface      Iface
	ifaceAllower InterfaceAllower
	mutex        sync.RWMutex

	incomingDenyRules   peerRules
	incomingAcceptRules peerRules
	incomingDenyIndex   peerRuleIndex
	incomingAcceptIndex peerRuleIndex
	peerRulesMap        map[nbid.RuleID]*PeerRule

	routeRules    routeRules
	routeRulesMap map[nbid.RuleID]*RouteRule

	// indicates whether server routes are disabled
	disableServerRoutes bool
	// indicates whether we forward packets not destined for ourselves
	routingEnabled atomic.Bool
	// indicates whether we leave forwarding and filtering to the native firewall
	nativeRouter atomic.Bool
	// indicates whether we track outbound connections
	stateful bool
	// indicates whether wireguards runs in netstack mode
	netstack bool
	// indicates whether we forward local traffic to the native stack
	localForwarding bool

	localipmanager *localIPManager

	udpTracker     *conntrack.UDPTracker
	icmpTracker    *conntrack.ICMPTracker
	tcpTracker     *conntrack.TCPTracker
	forwarder      atomic.Pointer[forwarder.Forwarder]
	pendingCapture atomic.Pointer[forwarder.PacketCapture]
	logger         *nblog.Logger
	flowLogger     nftypes.FlowLogger

	blockRules []firewall.Rule

	// Internal 1:1 DNAT
	dnatEnabled  atomic.Bool
	dnatMappings map[netip.Addr]netip.Addr
	dnatMutex    sync.RWMutex
	dnatBiMap    *biDNATMap

	portDNATEnabled atomic.Bool
	portDNATRules   []portDNATRule
	portDNATMutex   sync.RWMutex

	netstackServices     map[serviceKey]struct{}
	netstackServiceMutex sync.RWMutex

	mtu               uint16
	mssClampValueIPv4 uint16
	mssClampValueIPv6 uint16
	mssClampEnabled   bool

	// Only one hook per protocol is supported. Outbound direction only.
	udpHookOut atomic.Pointer[common.PacketHook]
	tcpHookOut atomic.Pointer[common.PacketHook]
}

// decoder for packages
type decoder struct {
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	decoded []gopacket.LayerType
	parser4 *gopacket.DecodingLayerParser
	parser6 *gopacket.DecodingLayerParser

	dnatOrigPort uint16
}

// decodePacket decodes packet data using the appropriate parser based on IP version.
func (d *decoder) decodePacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty packet")
	}
	version := data[0] >> 4
	switch version {
	case 4:
		return d.parser4.DecodeLayers(data, &d.decoded)
	case 6:
		return d.parser6.DecodeLayers(data, &d.decoded)
	default:
		return fmt.Errorf("unknown IP version %d", version)
	}
}

func parseCreateEnv() (bool, bool, bool) {
	var disableConntrack, enableLocalForwarding, disableMSSClamping bool
	var err error
	if val := os.Getenv(EnvDisableConntrack); val != "" {
		disableConntrack, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvDisableConntrack, err)
		}
	}
	if val := os.Getenv(EnvEnableNetstackLocalForwarding); val != "" {
		enableLocalForwarding, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvEnableNetstackLocalForwarding, err)
		}
	} else if val := os.Getenv(EnvEnableLocalForwarding); val != "" {
		enableLocalForwarding, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvEnableLocalForwarding, err)
		}
	}
	if val := os.Getenv(EnvDisableMSSClamping); val != "" {
		disableMSSClamping, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvDisableMSSClamping, err)
		}
	}

	return disableConntrack, enableLocalForwarding, disableMSSClamping
}

func Create(cfg Config) (_ *Manager, err error) {
	disableConntrack, enableLocalForwarding, disableMSSClamping := parseCreateEnv()

	m := &Manager{
		decoders: sync.Pool{
			New: func() any {
				d := &decoder{
					decoded: []gopacket.LayerType{},
				}
				d.parser4 = gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv4,
					&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
				)
				d.parser4.IgnoreUnsupported = true

				d.parser6 = gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv6,
					&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
				)
				d.parser6.IgnoreUnsupported = true
				return d
			},
		},
		wgIface:             cfg.IFace,
		ifaceAllower:        cfg.InterfaceAllower,
		localipmanager:      newLocalIPManager(),
		disableServerRoutes: cfg.DisableServerRoutes,
		stateful:            !disableConntrack,
		logger:              nblog.NewFromLogrus(log.StandardLogger()),
		flowLogger:          cfg.FlowLogger,
		netstack:            netstack.IsEnabled(),
		localForwarding:     enableLocalForwarding,
		peerRulesMap:        make(map[nbid.RuleID]*PeerRule),
		routeRulesMap:       make(map[nbid.RuleID]*RouteRule),
		dnatMappings:        make(map[netip.Addr]netip.Addr),
		portDNATRules:       []portDNATRule{},
		netstackServices:    make(map[serviceKey]struct{}),
		mtu:                 cfg.MTU,
	}
	m.routingEnabled.Store(false)

	// Release the allower (and its monitor) if setup fails after it was wired in.
	defer func() {
		if err != nil {
			m.closeAllowerOnError()
		}
	}()

	if !disableMSSClamping {
		m.enableMSSClamping(cfg.MTU)
	}
	if err := m.localipmanager.UpdateLocalIPs(cfg.IFace); err != nil {
		return nil, fmt.Errorf("update local IPs: %w", err)
	}
	m.setupConntrack(disableConntrack)
	if m.netstack && m.localForwarding {
		if err := m.initForwarder(); err != nil {
			log.Errorf("failed to initialize forwarder: %v", err)
		}
	}
	if err := cfg.IFace.SetFilter(m); err != nil {
		return nil, fmt.Errorf("set filter: %w", err)
	}

	m.openHostFirewall(cfg.IFace.Name())

	return m, nil
}

// closeAllowerOnError releases the allower (and its monitor) when Create fails
// after the allower was wired in.
func (m *Manager) closeAllowerOnError() {
	if m.ifaceAllower == nil {
		return
	}
	if err := m.ifaceAllower.Close(); err != nil {
		log.Warnf("close interface allower after failed firewall setup: %v", err)
	}
}

// enableMSSClamping enables MSS clamping and computes the per-family clamp values.
func (m *Manager) enableMSSClamping(mtu uint16) {
	m.mssClampEnabled = true
	if mtu > ipv4TCPHeaderMinSize {
		m.mssClampValueIPv4 = mtu - ipv4TCPHeaderMinSize
	}
	if mtu > ipv6TCPHeaderMinSize {
		m.mssClampValueIPv6 = mtu - ipv6TCPHeaderMinSize
	}
}

// setupConntrack initializes the stateful trackers unless conntrack is disabled.
func (m *Manager) setupConntrack(disabled bool) {
	if disabled {
		log.Info("conntrack is disabled")
		return
	}
	m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout, m.logger, m.flowLogger)
	m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout, m.logger, m.flowLogger)
	m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout, m.logger, m.flowLogger)
}

// openHostFirewall opens the NetBird interface in the kernel firewall so it
// doesn't drop traffic the userspace firewall handles. Best-effort: failures
// here shouldn't prevent the firewall from coming up.
func (m *Manager) openHostFirewall(ifaceName string) {
	if m.ifaceAllower != nil {
		if err := m.ifaceAllower.Apply(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
	}
	// firewalld owns its own chains we can't insert into, so trust the interface
	// there in addition to the allower. Netstack has no kernel interface.
	if !m.netstack {
		if err := firewalld.TrustInterface(ifaceName); err != nil {
			log.Warnf("failed to trust interface in firewalld: %v", err)
		}
	}
}

// Close cleans up the firewall manager: removes rules, closes trackers, and
// closes the interface allower.
func (m *Manager) Close(*statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.resetState()

	var merr *multierror.Error
	if m.ifaceAllower != nil {
		if err := m.ifaceAllower.Close(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("close interface allower: %w", err))
		}
	}
	if !m.netstack {
		if err := firewalld.UntrustInterface(m.wgIface.Name()); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("untrust interface in firewalld: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// blockInvalidRouted installs drop rules for traffic to the wg overlay that
// arrives via the routing path. v4 and v6 are independent: a v6 install
// failure leaves v4 protection in place (and vice versa) so the returned
// slice always contains whatever was successfully installed, even on error.
// Callers must persist the slice so DisableRouting can clean partial state.
func (m *Manager) blockInvalidRouted(iface Iface) ([]firewall.Rule, error) {
	wgPrefix := iface.Address().Network
	log.Debugf("blocking invalid routed traffic for %s", wgPrefix)

	sources := []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	v6Net := iface.Address().IPv6Net
	if v6Net.IsValid() {
		sources = append(sources, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	}

	var rules []firewall.Rule
	v4Rule, err := m.addRouteRule(
		nil,
		sources,
		firewall.Network{Prefix: wgPrefix},
		firewall.ProtocolALL,
		nil,
		nil,
		firewall.ActionDrop,
	)
	if err != nil {
		return rules, fmt.Errorf("block wg v4 net: %w", err)
	}
	rules = append(rules, v4Rule)

	if v6Net.IsValid() {
		log.Debugf("blocking invalid routed traffic for %s", v6Net)
		v6Rule, err := m.addRouteRule(
			nil,
			sources,
			firewall.Network{Prefix: v6Net},
			firewall.ProtocolALL,
			nil,
			nil,
			firewall.ActionDrop,
		)
		if err != nil {
			return rules, fmt.Errorf("block wg v6 net: %w", err)
		}
		rules = append(rules, v6Rule)
	}

	// TODO: Block networks that we're a client of

	return rules, nil
}

func (m *Manager) determineRouting() error {
	var disableUspRouting bool
	if val := os.Getenv(EnvDisableUserspaceRouting); val != "" {
		var err error
		disableUspRouting, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvDisableUserspaceRouting, err)
		}
	}

	switch {
	case disableUspRouting:
		m.routingEnabled.Store(false)
		m.nativeRouter.Store(false)
		log.Info("userspace routing is disabled")

	case m.disableServerRoutes:
		//  if server routes are disabled we will let packets pass to the native stack
		m.routingEnabled.Store(true)
		m.nativeRouter.Store(true)

		log.Info("server routes are disabled")

	default:
		m.routingEnabled.Store(true)
		m.nativeRouter.Store(false)

		log.Info("userspace routing enabled")
	}

	if m.routingEnabled.Load() && !m.nativeRouter.Load() {
		return m.initForwarder()
	}

	return nil
}

// SetPacketCapture sets or clears packet capture on the forwarder endpoint.
// This captures outbound response packets that bypass the FilteredDevice in netstack mode.
func (m *Manager) SetPacketCapture(pc forwarder.PacketCapture) {
	if pc == nil {
		m.pendingCapture.Store(nil)
	} else {
		m.pendingCapture.Store(&pc)
	}
	if fwder := m.forwarder.Load(); fwder != nil {
		fwder.SetCapture(pc)
	}
}

// initForwarder initializes the forwarder, it disables routing on errors
func (m *Manager) initForwarder() error {
	if m.forwarder.Load() != nil {
		return nil
	}

	// Only supported in userspace mode as we need to inject packets back into wireguard directly
	intf := m.wgIface.GetWGDevice()
	if intf == nil {
		m.routingEnabled.Store(false)
		return errors.New("forwarding not supported")
	}

	forwarder, err := forwarder.New(m.wgIface, m.logger, m.flowLogger, m.netstack, m.mtu)
	if err != nil {
		m.routingEnabled.Store(false)
		return fmt.Errorf("create forwarder: %w", err)
	}

	m.forwarder.Store(forwarder)

	// Re-load after store: a concurrent SetPacketCapture may have seen forwarder as nil and only updated pendingCapture.
	if pc := m.pendingCapture.Load(); pc != nil {
		forwarder.SetCapture(*pc)
	}

	log.Debug("forwarder initialized")

	return nil
}

func (m *Manager) Init(*statemanager.Manager) error {
	return nil
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) IsStateful() bool {
	return m.stateful
}

func (m *Manager) AddNatRule(firewall.RouterPair) error {
	// userspace routed packets are always SNATed to the inbound direction
	// TODO: implement outbound SNAT
	return nil
}

// RemoveNatRule removes a routing firewall rule
func (m *Manager) RemoveNatRule(firewall.RouterPair) error {
	return nil
}

// addPeerRule installs an input-chain rule that matches packets
// by source only. Called from AddFilterRule when the caller doesn't
// specify a destination. Sources are expected to share one address
// family; the family selects the ipLayer so the ICMP variant matches
// what the decoder produces.
func (m *Manager) addPeerRule(
	id []byte,
	sources []netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Sources are a single family; normalize v4-mapped prefixes to plain
	// v4 and pick the matching IP layer. A /0 source matches any address
	// of its own family only, mirroring the kernel backends.
	normalized := make([]netip.Prefix, len(sources))
	ipLayer := layers.LayerTypeIPv4
	for i, p := range sources {
		normalized[i] = firewall.UnmapPrefix(p)
		if normalized[i].Addr().Is6() {
			ipLayer = layers.LayerTypeIPv6
		}
	}
	spec := peerRuleSpec{
		mgmtID:  id,
		sources: normalized,
		ipLayer: ipLayer,
		proto:   proto,
		sPort:   sPort,
		dPort:   dPort,
		action:  action,
	}
	return m.addOnePeerRule(spec), nil
}

// addOnePeerRule builds and registers a single-family peer rule, or
// returns the existing rule when one with the same content key is
// already installed. The caller must hold m.mutex. The content key is
// the shared GenerateRuleID with an empty destination, so peer rules
// dedup the same way route rules and the kernel backends do; it is
// order-independent, so callers passing the same sources in any order
// dedup to one rule.
//
// There is no refcount: a content key is installed once and deleted on
// the first DeleteFilterRule for that key. The caller must therefore
// key its own tracking by the returned rule id so add and delete stay
// balanced per content key; the acl manager does this via
// peerRulesPairs.
func (m *Manager) addOnePeerRule(spec peerRuleSpec) *PeerRule {
	ruleID := nbid.GenerateRuleID(spec.sources, firewall.Network{}, spec.proto, spec.sPort, spec.dPort, spec.action)
	if existing, ok := m.peerRulesMap[ruleID]; ok {
		return existing
	}

	rule := m.buildPeerRule(ruleID, spec)
	m.registerPeerRule(rule)
	return rule
}

func (m *Manager) buildPeerRule(ruleID nbid.RuleID, spec peerRuleSpec) *PeerRule {
	r := &PeerRule{
		id:      ruleID,
		mgmtId:  spec.mgmtID,
		sources: spec.sources,
		action:  spec.action,
		srcPort: spec.sPort,
		dstPort: spec.dPort,
	}
	r.sourceAddrs = make(map[netip.Addr]struct{}, len(spec.sources))
	for _, p := range spec.sources {
		if p.Bits() == p.Addr().BitLen() {
			r.sourceAddrs[p.Addr()] = struct{}{}
		}
	}
	r.protoLayer = protoToLayer(spec.proto, spec.ipLayer)
	return r
}

// registerPeerRule records a freshly built peer rule in the matching
// slice, index, and dedup map. The caller must hold m.mutex.
func (m *Manager) registerPeerRule(r *PeerRule) {
	if r.action == firewall.ActionDrop {
		m.incomingDenyRules = append(m.incomingDenyRules, r)
		m.incomingDenyIndex.add(r)
	} else {
		m.incomingAcceptRules = append(m.incomingAcceptRules, r)
		m.incomingAcceptIndex.add(r)
	}
	m.peerRulesMap[r.id] = r
}

// AddFilterRule is the unified entry point for both peer (input chain)
// and route (forward chain) filtering rules. The destination
// distinguishes the two semantics: a zero Network installs an
// input-side rule that matches by source only; a set Network installs
// a forward-side rule that also matches the destination.
func (m *Manager) AddFilterRule(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	if len(sources) == 0 {
		return nil, firewall.ErrNoSources
	}

	if destination.IsZero() {
		return m.addPeerRule(id, sources, proto, sPort, dPort, action)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.addRouteRule(id, sources, destination, proto, sPort, dPort, action)
}

// DeleteFilterRule deletes a filtering rule. The rule's underlying type
// is used to route to the correct internal path.
func (m *Manager) DeleteFilterRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if r, ok := rule.(*PeerRule); ok {
		return m.deletePeerRuleLocked(r)
	}

	// Anything else is a route rule (matched on the forward path).
	return m.deleteRouteRule(rule)
}

func (m *Manager) addRouteRule(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	ruleID := nbid.GenerateRuleID(sources, destination, proto, sPort, dPort, action)

	if existingRule, ok := m.routeRulesMap[ruleID]; ok {
		return existingRule, nil
	}

	rule := RouteRule{
		id:         ruleID,
		mgmtId:     id,
		sources:    sources,
		dstSet:     destination.Set,
		protoLayer: protoToLayer(proto, ipLayerFromPrefix(destination.Prefix)),
		srcPort:    sPort,
		dstPort:    dPort,
		action:     action,
	}
	if destination.IsPrefix() {
		rule.destinations = []netip.Prefix{destination.Prefix}
	}

	m.routeRules = append(m.routeRules, &rule)
	m.routeRules.Sort()
	m.routeRulesMap[ruleID] = &rule

	return &rule, nil
}

func (m *Manager) deleteRouteRule(rule firewall.Rule) error {
	ruleID := rule.ID()
	trimmed, _, ok := removeRuleByID(m.routeRules, ruleID)
	if !ok {
		return fmt.Errorf("route rule not found: %s", ruleID)
	}
	m.routeRules = trimmed
	delete(m.routeRulesMap, ruleID)
	return nil
}

// deletePeerRuleLocked removes a peer rule from the matching slice,
// index, and dedup map. The caller must hold m.mutex.
func (m *Manager) deletePeerRuleLocked(r *PeerRule) error {
	target, index := &m.incomingAcceptRules, &m.incomingAcceptIndex
	if r.action == firewall.ActionDrop {
		target, index = &m.incomingDenyRules, &m.incomingDenyIndex
	}

	trimmed, stored, ok := removeRuleByID(*target, r.id)
	if !ok {
		return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
	}
	*target = trimmed
	index.remove(stored)
	delete(m.peerRulesMap, r.id)
	return nil
}

// removeRuleByID removes the first rule whose id matches ruleID from
// rules, preserving order. It returns the trimmed slice, the removed
// rule, and whether a match was found.
func removeRuleByID[S ~[]T, T firewall.Rule](rules S, ruleID firewall.RuleID) (S, T, bool) {
	idx := slices.IndexFunc(rules, func(r T) bool { return r.ID() == ruleID })
	var removed T
	if idx < 0 {
		return rules, removed, false
	}
	removed = rules[idx]
	return slices.Delete(rules, idx, idx+1), removed, true
}

// SetLegacyManagement is a no-op for the userspace firewall: it only matters
// when an old management server can't send route firewall rules, which the
// userspace router doesn't rely on.
func (m *Manager) SetLegacyManagement(bool) error {
	return nil
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

// resetState clears all firewall rules and closes connection trackers.
// Must be called with m.mutex held.
func (m *Manager) resetState() {
	m.incomingDenyRules = m.incomingDenyRules[:0]
	m.incomingAcceptRules = m.incomingAcceptRules[:0]
	m.incomingDenyIndex.reset()
	m.incomingAcceptIndex.reset()
	clear(m.peerRulesMap)
	clear(m.routeRulesMap)
	m.routeRules = m.routeRules[:0]
	m.blockRules = nil
	m.udpHookOut.Store(nil)
	m.tcpHookOut.Store(nil)

	if m.udpTracker != nil {
		m.udpTracker.Close()
	}

	if m.icmpTracker != nil {
		m.icmpTracker.Close()
	}

	if m.tcpTracker != nil {
		m.tcpTracker.Close()
	}

	if fwder := m.forwarder.Load(); fwder != nil {
		fwder.SetCapture(nil)
		fwder.Stop()
	}

	if m.logger != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.logger.Stop(ctx); err != nil {
			log.Errorf("failed to shutdown logger: %v", err)
		}
	}
}

// SetupEBPFProxyNoTrack is not supported by the userspace firewall: eBPF isn't
// used in userspace mode, so this should never be called.
func (m *Manager) SetupEBPFProxyNoTrack(uint16, uint16) error {
	return errNotSupported
}

// UpdateSet updates the rule destinations associated with the given set
// by merging the existing prefixes with the new ones, then deduplicating.
func (m *Manager) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var matches []*RouteRule
	for _, rule := range m.routeRules {
		if rule.dstSet == set {
			matches = append(matches, rule)
		}
	}

	if len(matches) == 0 {
		return fmt.Errorf("no route rule found for set: %s", set)
	}

	destinations := matches[0].destinations
	destinations = append(destinations, prefixes...)

	slices.SortFunc(destinations, func(a, b netip.Prefix) int {
		cmp := a.Addr().Compare(b.Addr())
		if cmp != 0 {
			return cmp
		}
		return a.Bits() - b.Bits()
	})

	destinations = slices.Compact(destinations)

	for _, rule := range matches {
		rule.destinations = destinations
	}
	log.Debugf("updated set %s to prefixes %v", set.HashedName(), destinations)

	return nil
}

// FilterOutbound filters outgoing packets
func (m *Manager) FilterOutbound(packetData []byte, size int) bool {
	return m.filterOutbound(packetData, size)
}

// FilterInbound filters incoming packets
func (m *Manager) FilterInbound(packetData []byte, size int) bool {
	return m.filterInbound(packetData, size)
}

// UpdateLocalIPs updates the list of local IPs
func (m *Manager) UpdateLocalIPs() error {
	return m.localipmanager.UpdateLocalIPs(m.wgIface)
}

func (m *Manager) filterOutbound(packetData []byte, size int) bool {
	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if err := d.decodePacket(packetData); err != nil {
		return false
	}

	if len(d.decoded) < 2 {
		return false
	}

	srcIP, dstIP := m.extractIPs(d)
	if !srcIP.IsValid() {
		if m.logger.Enabled(nblog.LevelError) {
			m.logger.Error1("Unknown network layer: %v", d.decoded[0])
		}
		return false
	}

	switch d.decoded[1] {
	case layers.LayerTypeUDP:
		if m.udpHooksDrop(uint16(d.udp.DstPort), dstIP, packetData) {
			return true
		}
	case layers.LayerTypeTCP:
		if m.tcpHooksDrop(uint16(d.tcp.DstPort), dstIP, packetData) {
			return true
		}
		// Clamp MSS on all TCP SYN packets, including those from local IPs.
		// SNATed routed traffic may appear as local IP but still requires clamping.
		if m.mssClampEnabled {
			m.clampTCPMSS(packetData, d)
		}
	}

	m.trackOutbound(d, srcIP, dstIP, packetData, size)
	m.translateOutboundDNAT(packetData, d)

	return false
}

func (m *Manager) extractIPs(d *decoder) (srcIP, dstIP netip.Addr) {
	switch d.decoded[0] {
	case layers.LayerTypeIPv4:
		src, _ := netip.AddrFromSlice(d.ip4.SrcIP)
		dst, _ := netip.AddrFromSlice(d.ip4.DstIP)
		return src.Unmap(), dst.Unmap()
	case layers.LayerTypeIPv6:
		src, _ := netip.AddrFromSlice(d.ip6.SrcIP)
		dst, _ := netip.AddrFromSlice(d.ip6.DstIP)
		return src.Unmap(), dst.Unmap()
	default:
		return netip.Addr{}, netip.Addr{}
	}
}

func getTCPFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.SYN {
		flags |= conntrack.TCPSyn
	}
	if tcp.ACK {
		flags |= conntrack.TCPAck
	}
	if tcp.FIN {
		flags |= conntrack.TCPFin
	}
	if tcp.RST {
		flags |= conntrack.TCPRst
	}
	if tcp.PSH {
		flags |= conntrack.TCPPush
	}
	if tcp.URG {
		flags |= conntrack.TCPUrg
	}
	return flags
}

// clampTCPMSS clamps the TCP MSS option in SYN and SYN-ACK packets to prevent fragmentation.
// Both sides advertise their MSS during connection establishment, so we need to clamp both.
func (m *Manager) clampTCPMSS(packetData []byte, d *decoder) bool {
	if !d.tcp.SYN {
		return false
	}
	if len(d.tcp.Options) == 0 {
		return false
	}

	var mssClampValue uint16
	var ipHeaderSize int
	switch d.decoded[0] {
	case layers.LayerTypeIPv4:
		mssClampValue = m.mssClampValueIPv4
		ipHeaderSize = int(d.ip4.IHL) * 4
		if ipHeaderSize < 20 {
			return false
		}
	case layers.LayerTypeIPv6:
		mssClampValue = m.mssClampValueIPv6
		ipHeaderSize = 40
	default:
		return false
	}

	if mssClampValue == 0 {
		return false
	}

	mssOptionIndex := -1
	var currentMSS uint16
	for i, opt := range d.tcp.Options {
		if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) == 2 {
			currentMSS = binary.BigEndian.Uint16(opt.OptionData)
			if currentMSS > mssClampValue {
				mssOptionIndex = i
				break
			}
		}
	}

	if mssOptionIndex == -1 {
		return false
	}

	if !m.updateMSSOption(packetData, d, mssOptionIndex, mssClampValue, ipHeaderSize) {
		return false
	}

	if m.logger.Enabled(nblog.LevelTrace) {
		m.logger.Trace2("Clamped TCP MSS from %d to %d", currentMSS, mssClampValue)
	}
	return true
}

func (m *Manager) updateMSSOption(packetData []byte, d *decoder, mssOptionIndex int, mssClampValue uint16, ipHeaderSize int) bool {
	tcpHeaderStart := ipHeaderSize
	tcpOptionsStart := tcpHeaderStart + 20

	optOffset := tcpOptionsStart
	for j := 0; j < mssOptionIndex; j++ {
		switch d.tcp.Options[j].OptionType {
		case layers.TCPOptionKindEndList, layers.TCPOptionKindNop:
			optOffset++
		default:
			optOffset += 2 + len(d.tcp.Options[j].OptionData)
		}
	}

	mssValueOffset := optOffset + 2
	binary.BigEndian.PutUint16(packetData[mssValueOffset:mssValueOffset+2], mssClampValue)

	m.recalculateTCPChecksum(packetData, d, tcpHeaderStart)
	return true
}

func (m *Manager) recalculateTCPChecksum(packetData []byte, d *decoder, tcpHeaderStart int) {
	tcpLayer := packetData[tcpHeaderStart:]
	tcpLength := len(packetData) - tcpHeaderStart

	// Zero out existing checksum
	tcpLayer[16] = 0
	tcpLayer[17] = 0

	// Build pseudo-header checksum based on IP version
	var pseudoSum uint32
	switch d.decoded[0] {
	case layers.LayerTypeIPv4:
		pseudoSum += uint32(d.ip4.SrcIP[0])<<8 | uint32(d.ip4.SrcIP[1])
		pseudoSum += uint32(d.ip4.SrcIP[2])<<8 | uint32(d.ip4.SrcIP[3])
		pseudoSum += uint32(d.ip4.DstIP[0])<<8 | uint32(d.ip4.DstIP[1])
		pseudoSum += uint32(d.ip4.DstIP[2])<<8 | uint32(d.ip4.DstIP[3])
		pseudoSum += uint32(d.ip4.Protocol)
		pseudoSum += uint32(tcpLength)
	case layers.LayerTypeIPv6:
		for i := 0; i < 16; i += 2 {
			pseudoSum += uint32(d.ip6.SrcIP[i])<<8 | uint32(d.ip6.SrcIP[i+1])
		}
		for i := 0; i < 16; i += 2 {
			pseudoSum += uint32(d.ip6.DstIP[i])<<8 | uint32(d.ip6.DstIP[i+1])
		}
		pseudoSum += uint32(tcpLength)
		pseudoSum += uint32(layers.IPProtocolTCP)
	}

	sum := pseudoSum
	for i := 0; i < tcpLength-1; i += 2 {
		sum += uint32(tcpLayer[i])<<8 | uint32(tcpLayer[i+1])
	}
	if tcpLength%2 == 1 {
		sum += uint32(tcpLayer[tcpLength-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(tcpLayer[16:18], checksum)
}

func (m *Manager) trackOutbound(d *decoder, srcIP, dstIP netip.Addr, packetData []byte, size int) {
	transport := d.decoded[1]
	switch transport {
	case layers.LayerTypeUDP:
		origPort := m.udpTracker.TrackOutbound(srcIP, dstIP, uint16(d.udp.SrcPort), uint16(d.udp.DstPort), size)
		if origPort == 0 {
			break
		}
		if err := m.rewriteUDPPort(packetData, d, origPort, sourcePortOffset); err != nil {
			m.logger.Error1("failed to rewrite UDP port: %v", err)
		}
	case layers.LayerTypeTCP:
		flags := getTCPFlags(&d.tcp)
		origPort := m.tcpTracker.TrackOutbound(srcIP, dstIP, uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort), flags, size)
		if origPort == 0 {
			break
		}
		if err := m.rewriteTCPPort(packetData, d, origPort, sourcePortOffset); err != nil {
			m.logger.Error1("failed to rewrite TCP port: %v", err)
		}
	case layers.LayerTypeICMPv4:
		m.icmpTracker.TrackOutbound(srcIP, dstIP, d.icmp4.Id, d.icmp4.TypeCode, d.icmp4.Payload, size)
	case layers.LayerTypeICMPv6:
		id, tc := icmpv6EchoFields(d)
		m.icmpTracker.TrackOutbound(srcIP, dstIP, id, tc, d.icmp6.Payload, size)
	}
}

func (m *Manager) trackInbound(d *decoder, srcIP, dstIP netip.Addr, ruleID []byte, size int) {
	transport := d.decoded[1]
	switch transport {
	case layers.LayerTypeUDP:
		m.udpTracker.TrackInbound(srcIP, dstIP, uint16(d.udp.SrcPort), uint16(d.udp.DstPort), ruleID, size, d.dnatOrigPort)
	case layers.LayerTypeTCP:
		flags := getTCPFlags(&d.tcp)
		m.tcpTracker.TrackInbound(srcIP, dstIP, uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort), flags, ruleID, size, d.dnatOrigPort)
	case layers.LayerTypeICMPv4:
		m.icmpTracker.TrackInbound(srcIP, dstIP, d.icmp4.Id, d.icmp4.TypeCode, ruleID, d.icmp4.Payload, size)
	case layers.LayerTypeICMPv6:
		id, tc := icmpv6EchoFields(d)
		m.icmpTracker.TrackInbound(srcIP, dstIP, id, tc, ruleID, d.icmp6.Payload, size)
	}

	d.dnatOrigPort = 0
}

func (m *Manager) udpHooksDrop(dport uint16, dstIP netip.Addr, packetData []byte) bool {
	return common.HookMatches(m.udpHookOut.Load(), dstIP, dport, packetData)
}

func (m *Manager) tcpHooksDrop(dport uint16, dstIP netip.Addr, packetData []byte) bool {
	return common.HookMatches(m.tcpHookOut.Load(), dstIP, dport, packetData)
}

// filterInbound implements filtering logic for incoming packets.
// If it returns true, the packet should be dropped.
func (m *Manager) filterInbound(packetData []byte, size int) bool {
	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	valid, fragment := m.isValidPacket(d, packetData)
	if !valid {
		return true
	}

	srcIP, dstIP := m.extractIPs(d)
	if !srcIP.IsValid() {
		m.logger.Error1("Unknown network layer: %v", d.decoded[0])
		return true
	}

	// TODO: pass fragments of routed packets to forwarder
	if fragment {
		if m.logger.Enabled(nblog.LevelTrace) {
			if d.decoded[0] == layers.LayerTypeIPv4 {
				m.logger.Trace4("packet is a fragment: src=%v dst=%v id=%v flags=%v",
					srcIP, dstIP, d.ip4.Id, d.ip4.Flags)
			} else {
				m.logger.Trace2("packet is an IPv6 fragment: src=%v dst=%v", srcIP, dstIP)
			}
		}
		return false
	}

	// TODO: optimize port DNAT by caching matched rules in conntrack
	if translated := m.translateInboundPortDNAT(packetData, d, srcIP, dstIP); translated {
		// Re-decode after port DNAT translation to update port information
		if err := d.decodePacket(packetData); err != nil {
			m.logger.Error1("failed to re-decode packet after port DNAT: %v", err)
			return true
		}
		srcIP, dstIP = m.extractIPs(d)
	}

	if translated := m.translateInboundReverse(packetData, d); translated {
		// Re-decode after translation to get original addresses
		if err := d.decodePacket(packetData); err != nil {
			m.logger.Error1("failed to re-decode packet after reverse DNAT: %v", err)
			return true
		}
		srcIP, dstIP = m.extractIPs(d)
	}

	if m.stateful && m.isValidTrackedConnection(d, srcIP, dstIP, size) {
		return false
	}

	if m.localipmanager.IsLocalIP(dstIP) {
		return m.handleLocalTraffic(d, srcIP, dstIP, packetData, size)
	}

	return m.handleRoutedTraffic(d, srcIP, dstIP, packetData, size)
}

// handleLocalTraffic handles local traffic.
// If it returns true, the packet should be dropped.
func (m *Manager) handleLocalTraffic(d *decoder, srcIP, dstIP netip.Addr, packetData []byte, size int) bool {
	ruleID, blocked := m.peerACLsBlock(srcIP, d, packetData)
	if blocked {
		pnum := getProtocolFromPacket(d)
		srcPort, dstPort := getPortsFromPacket(d)

		if m.logger.Enabled(nblog.LevelTrace) {
			m.logger.Trace6("Dropping local packet (ACL denied): rule_id=%s proto=%v src=%s:%d dst=%s:%d",
				ruleID, pnum, srcIP, srcPort, dstIP, dstPort)
		}

		m.flowLogger.StoreEvent(nftypes.EventFields{
			FlowID:     uuid.New(),
			Type:       nftypes.TypeDrop,
			RuleID:     ruleID,
			Direction:  nftypes.Ingress,
			Protocol:   pnum,
			SourceIP:   srcIP,
			DestIP:     dstIP,
			SourcePort: srcPort,
			DestPort:   dstPort,
			// TODO: icmp type/code
			RxPackets: 1,
			RxBytes:   uint64(size),
		})
		return true
	}

	if m.shouldForward(d, dstIP) {
		return m.handleForwardedLocalTraffic(packetData)
	}

	// track inbound packets to get the correct direction and session id for flows
	m.trackInbound(d, srcIP, dstIP, ruleID, size)

	// pass to either native or virtual stack (to be picked up by listeners)
	return false
}

func (m *Manager) handleForwardedLocalTraffic(packetData []byte) bool {
	fwd := m.forwarder.Load()
	if fwd == nil {
		m.logger.Trace("Dropping local packet (forwarder not initialized)")
		return true
	}

	if err := fwd.InjectIncomingPacket(packetData); err != nil {
		m.logger.Error1("Failed to inject local packet: %v", err)
	}

	// don't process this packet further
	return true
}

// handleRoutedTraffic handles routed traffic.
// If it returns true, the packet should be dropped.
func (m *Manager) handleRoutedTraffic(d *decoder, srcIP, dstIP netip.Addr, packetData []byte, size int) bool {
	// Drop if routing is disabled
	if !m.routingEnabled.Load() {
		if m.logger.Enabled(nblog.LevelTrace) {
			m.logger.Trace2("Dropping routed packet (routing disabled): src=%s dst=%s",
				srcIP, dstIP)
		}
		return true
	}

	// Pass to native stack if native router is enabled or forced
	if m.nativeRouter.Load() {
		m.trackInbound(d, srcIP, dstIP, nil, size)
		return false
	}

	protoLayer := d.decoded[1]
	srcPort, dstPort := getPortsFromPacket(d)

	ruleID, pass := m.routeACLsPass(srcIP, dstIP, protoLayer, srcPort, dstPort)
	if !pass {
		proto := getProtocolFromPacket(d)

		if m.logger.Enabled(nblog.LevelTrace) {
			m.logger.Trace6("Dropping routed packet (ACL denied): rule_id=%s proto=%v src=%s:%d dst=%s:%d",
				ruleID, proto, srcIP, srcPort, dstIP, dstPort)
		}

		m.flowLogger.StoreEvent(nftypes.EventFields{
			FlowID:     uuid.New(),
			Type:       nftypes.TypeDrop,
			RuleID:     ruleID,
			Direction:  nftypes.Ingress,
			Protocol:   proto,
			SourceIP:   srcIP,
			DestIP:     dstIP,
			SourcePort: srcPort,
			DestPort:   dstPort,
			// TODO: icmp type/code
			RxPackets: 1,
			RxBytes:   uint64(size),
		})
		return true
	}

	// Let forwarder handle the packet if it passed route ACLs
	fwd := m.forwarder.Load()
	if fwd == nil {
		m.logger.Trace("failed to forward routed packet (forwarder not initialized)")
	} else {
		fwd.RegisterRuleID(srcIP, dstIP, srcPort, dstPort, ruleID)

		if err := fwd.InjectIncomingPacket(packetData); err != nil {
			m.logger.Error1("Failed to inject routed packet: %v", err)
			fwd.DeleteRuleID(srcIP, dstIP, srcPort, dstPort)
		}
	}

	// Forwarded packets shouldn't reach the native stack, hence they won't be visible in a packet capture
	return true
}

// icmpv6EchoFields extracts the echo identifier from an ICMPv6 packet and maps
// the ICMPv6 type code to an ICMPv4TypeCode so the ICMP conntrack can handle
// both families uniformly. The echo ID is in the first two payload bytes.
func icmpv6EchoFields(d *decoder) (id uint16, tc layers.ICMPv4TypeCode) {
	if len(d.icmp6.Payload) >= 2 {
		id = uint16(d.icmp6.Payload[0])<<8 | uint16(d.icmp6.Payload[1])
	}
	// Map ICMPv6 echo types to ICMPv4 equivalents for unified tracking.
	switch d.icmp6.TypeCode.Type() {
	case layers.ICMPv6TypeEchoRequest:
		tc = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	case layers.ICMPv6TypeEchoReply:
		tc = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)
	default:
		tc = layers.CreateICMPv4TypeCode(d.icmp6.TypeCode.Type(), d.icmp6.TypeCode.Code())
	}
	return id, tc
}

// protoLayerMatches checks if a packet's protocol layer matches a rule's expected
// protocol layer. ICMPv4 and ICMPv6 are treated as equivalent when matching
// ICMP rules since management sends a single ICMP rule for both families.
func protoLayerMatches(ruleLayer, packetLayer gopacket.LayerType) bool {
	if ruleLayer == packetLayer {
		return true
	}
	if ruleLayer == layers.LayerTypeICMPv4 && packetLayer == layers.LayerTypeICMPv6 {
		return true
	}
	if ruleLayer == layers.LayerTypeICMPv6 && packetLayer == layers.LayerTypeICMPv4 {
		return true
	}
	return false
}

func ipLayerFromPrefix(p netip.Prefix) gopacket.LayerType {
	if p.Addr().Is6() {
		return layers.LayerTypeIPv6
	}
	return layers.LayerTypeIPv4
}

func protoToLayer(proto firewall.Protocol, ipLayer gopacket.LayerType) gopacket.LayerType {
	switch proto {
	case firewall.ProtocolTCP:
		return layers.LayerTypeTCP
	case firewall.ProtocolUDP:
		return layers.LayerTypeUDP
	case firewall.ProtocolICMP:
		if ipLayer == layers.LayerTypeIPv6 {
			return layers.LayerTypeICMPv6
		}
		return layers.LayerTypeICMPv4
	case firewall.ProtocolALL:
		return layerTypeAll
	}
	return 0
}

func getProtocolFromPacket(d *decoder) nftypes.Protocol {
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return nftypes.TCP
	case layers.LayerTypeUDP:
		return nftypes.UDP
	case layers.LayerTypeICMPv4:
		return nftypes.ICMP
	case layers.LayerTypeICMPv6:
		return nftypes.ICMPv6
	default:
		return nftypes.ProtocolUnknown
	}
}

func getPortsFromPacket(d *decoder) (srcPort, dstPort uint16) {
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
	case layers.LayerTypeUDP:
		return uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
	default:
		return 0, 0
	}
}

// isValidPacket checks if the packet is valid.
// It returns true, false if the packet is valid and not a fragment.
// It returns true, true if the packet is a fragment and valid.
func (m *Manager) isValidPacket(d *decoder, packetData []byte) (bool, bool) {
	if err := d.decodePacket(packetData); err != nil {
		if m.logger.Enabled(nblog.LevelTrace) {
			m.logger.Trace1("couldn't decode packet, err: %s", err)
		}
		return false, false
	}

	l := len(d.decoded)

	// L3 and L4 are mandatory
	if l >= 2 {
		return true, false
	}

	// Fragments are also valid
	if l == 1 {
		switch d.decoded[0] {
		case layers.LayerTypeIPv4:
			if d.ip4.Flags&layers.IPv4MoreFragments != 0 || d.ip4.FragOffset != 0 {
				return true, true
			}
		case layers.LayerTypeIPv6:
			// IPv6 uses Fragment extension header (NextHeader=44). If gopacket
			// only decoded the IPv6 layer, the transport is in a fragment.
			// TODO: handle non-Fragment extension headers (HopByHop, Routing,
			// DestOpts) by walking the chain. gopacket's parser does not
			// support them as DecodingLayers; today we drop such packets.
			if d.ip6.NextHeader == layers.IPProtocolIPv6Fragment {
				return true, true
			}
		}
	}

	m.logger.Trace("packet doesn't have network and transport layers")
	return false, false
}

func (m *Manager) isValidTrackedConnection(d *decoder, srcIP, dstIP netip.Addr, size int) bool {
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return m.tcpTracker.IsValidInbound(
			srcIP,
			dstIP,
			uint16(d.tcp.SrcPort),
			uint16(d.tcp.DstPort),
			getTCPFlags(&d.tcp),
			size,
		)

	case layers.LayerTypeUDP:
		return m.udpTracker.IsValidInbound(
			srcIP,
			dstIP,
			uint16(d.udp.SrcPort),
			uint16(d.udp.DstPort),
			size,
		)

	case layers.LayerTypeICMPv4:
		return m.icmpTracker.IsValidInbound(
			srcIP,
			dstIP,
			d.icmp4.Id,
			d.icmp4.TypeCode.Type(),
			size,
		)

	case layers.LayerTypeICMPv6:
		id, _ := icmpv6EchoFields(d)
		return m.icmpTracker.IsValidInbound(
			srcIP,
			dstIP,
			id,
			d.icmp6.TypeCode.Type(),
			size,
		)
	}

	return false
}

// isSpecialICMP returns true if the packet is a special ICMP error packet that should be allowed.
func (m *Manager) isSpecialICMP(d *decoder) bool {
	switch d.decoded[1] {
	case layers.LayerTypeICMPv4:
		icmpType := d.icmp4.TypeCode.Type()
		return icmpType == layers.ICMPv4TypeDestinationUnreachable ||
			icmpType == layers.ICMPv4TypeTimeExceeded
	case layers.LayerTypeICMPv6:
		icmpType := d.icmp6.TypeCode.Type()
		return icmpType == layers.ICMPv6TypeDestinationUnreachable ||
			icmpType == layers.ICMPv6TypePacketTooBig ||
			icmpType == layers.ICMPv6TypeTimeExceeded ||
			icmpType == layers.ICMPv6TypeParameterProblem
	}
	return false
}

func (m *Manager) peerACLsBlock(srcIP netip.Addr, d *decoder, packetData []byte) ([]byte, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.isSpecialICMP(d) {
		return nil, false
	}

	if mgmtId, filter, ok := m.incomingDenyIndex.match(srcIP, d); ok {
		return mgmtId, filter
	}
	if mgmtId, filter, ok := m.incomingAcceptIndex.match(srcIP, d); ok {
		return mgmtId, filter
	}
	return nil, true
}

func portsMatch(rulePort *firewall.Port, packetPort uint16) bool {
	if rulePort == nil {
		return true
	}

	if rulePort.IsRange {
		return packetPort >= rulePort.Values[0] && packetPort <= rulePort.Values[1]
	}

	for _, p := range rulePort.Values {
		if p == packetPort {
			return true
		}
	}
	return false
}

// routeACLsPass returns true if the packet is allowed by the route ACLs
func (m *Manager) routeACLsPass(srcIP, dstIP netip.Addr, protoLayer gopacket.LayerType, srcPort, dstPort uint16) ([]byte, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, rule := range m.routeRules {
		if matches := m.ruleMatches(rule, srcIP, dstIP, protoLayer, srcPort, dstPort); matches {
			return rule.mgmtId, rule.action == firewall.ActionAccept
		}
	}
	return nil, false
}

func (m *Manager) ruleMatches(rule *RouteRule, srcAddr, dstAddr netip.Addr, protoLayer gopacket.LayerType, srcPort, dstPort uint16) bool {
	if rule.protoLayer != layerTypeAll && !protoLayerMatches(rule.protoLayer, protoLayer) {
		return false
	}

	if protoLayer == layers.LayerTypeTCP || protoLayer == layers.LayerTypeUDP {
		if !portsMatch(rule.srcPort, srcPort) || !portsMatch(rule.dstPort, dstPort) {
			return false
		}
	}

	destMatched := false
	for _, dst := range rule.destinations {
		if dst.Contains(dstAddr) {
			destMatched = true
			break
		}
	}
	if !destMatched {
		return false
	}

	sourceMatched := false
	for _, src := range rule.sources {
		if src.Contains(srcAddr) {
			sourceMatched = true
			break
		}
	}

	return sourceMatched
}

// SetUDPPacketHook sets the outbound UDP packet hook. Pass nil hook to remove.
func (m *Manager) SetUDPPacketHook(ip netip.Addr, dPort uint16, hook func(packet []byte) bool) {
	common.SetHook(&m.udpHookOut, ip, dPort, hook)
}

// SetTCPPacketHook sets the outbound TCP packet hook. Pass nil hook to remove.
func (m *Manager) SetTCPPacketHook(ip netip.Addr, dPort uint16, hook func(packet []byte) bool) {
	common.SetHook(&m.tcpHookOut, ip, dPort, hook)
}

// SetLogLevel sets the log level for the firewall manager
func (m *Manager) SetLogLevel(level log.Level) {
	if m.logger != nil {
		m.logger.SetLevel(nblog.Level(level))
	}
}

func (m *Manager) EnableRouting() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.determineRouting(); err != nil {
		return fmt.Errorf("determine routing: %w", err)
	}

	if m.forwarder.Load() == nil {
		return nil
	}

	rules, err := m.blockInvalidRouted(m.wgIface)
	m.blockRules = rules
	if err != nil {
		// Roll back so forwarding can't stay active without the full set of
		// block rules.
		if derr := m.disableRouting(); derr != nil {
			log.Warnf("roll back routing after block rule failure: %v", derr)
		}
		return fmt.Errorf("block invalid routed: %w", err)
	}

	return nil
}

func (m *Manager) DisableRouting() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.disableRouting()
}

func (m *Manager) disableRouting() error {
	fwder := m.forwarder.Load()
	if fwder == nil {
		return nil
	}

	m.routingEnabled.Store(false)
	m.nativeRouter.Store(false)

	var merr *multierror.Error
	for _, rule := range m.blockRules {
		if err := m.deleteRouteRule(rule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete block rule: %w", err))
		}
	}
	m.blockRules = nil

	if m.netstack && m.localForwarding {
		return nberrors.FormatErrorOrNil(merr)
	}

	fwder.Stop()
	m.forwarder.Store(nil)

	log.Debug("forwarder stopped")

	return nberrors.FormatErrorOrNil(merr)
}

// RegisterNetstackService registers a service as listening on the netstack for the given protocol and port
func (m *Manager) RegisterNetstackService(protocol nftypes.Protocol, port uint16) {
	m.netstackServiceMutex.Lock()
	defer m.netstackServiceMutex.Unlock()
	layerType := m.protocolToLayerType(protocol)
	key := serviceKey{protocol: layerType, port: port}
	m.netstackServices[key] = struct{}{}
	m.logger.Debug3("RegisterNetstackService: registered %s:%d (layerType=%s)", protocol, port, layerType)
	m.logger.Debug1("RegisterNetstackService: current registry size: %d", len(m.netstackServices))
}

// UnregisterNetstackService removes a service from the netstack registry
func (m *Manager) UnregisterNetstackService(protocol nftypes.Protocol, port uint16) {
	m.netstackServiceMutex.Lock()
	defer m.netstackServiceMutex.Unlock()
	layerType := m.protocolToLayerType(protocol)
	key := serviceKey{protocol: layerType, port: port}
	delete(m.netstackServices, key)
	m.logger.Debug2("Unregistered netstack service on protocol %s port %d", protocol, port)
}

// protocolToLayerType converts nftypes.Protocol to gopacket.LayerType for internal use
func (m *Manager) protocolToLayerType(protocol nftypes.Protocol) gopacket.LayerType {
	switch protocol {
	case nftypes.TCP:
		return layers.LayerTypeTCP
	case nftypes.UDP:
		return layers.LayerTypeUDP
	case nftypes.ICMP:
		return layers.LayerTypeICMPv4
	default:
		return gopacket.LayerType(0) // Invalid/unknown
	}
}

// shouldForward determines if a packet should be forwarded to the forwarder.
// The forwarder handles routing packets to the native OS network stack.
// Returns true if packet should go to the forwarder, false if it should go to netstack listeners or the native stack directly.
func (m *Manager) shouldForward(d *decoder, dstIP netip.Addr) bool {
	// not enabled, never forward
	if !m.localForwarding {
		return false
	}

	// netstack always needs to forward because it's lacking a native interface
	// exception for registered netstack services, those should go to netstack listeners
	if m.netstack {
		return !m.hasMatchingNetstackService(d)
	}

	// traffic to our other local interfaces (not NetBird IP) - always forward
	addr := m.wgIface.Address()
	if dstIP != addr.IP && (!addr.IPv6.IsValid() || dstIP != addr.IPv6) {
		return true
	}

	// traffic to our NetBird IP, not netstack mode - send to netstack listeners
	return false
}

// hasMatchingNetstackService checks if there's a registered netstack service for this packet
func (m *Manager) hasMatchingNetstackService(d *decoder) bool {
	if len(d.decoded) < 2 {
		return false
	}

	var dstPort uint16
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		dstPort = uint16(d.tcp.DstPort)
	case layers.LayerTypeUDP:
		dstPort = uint16(d.udp.DstPort)
	default:
		return false
	}

	key := serviceKey{protocol: d.decoded[1], port: dstPort}
	m.netstackServiceMutex.RLock()
	_, exists := m.netstackServices[key]
	m.netstackServiceMutex.RUnlock()

	return exists
}
