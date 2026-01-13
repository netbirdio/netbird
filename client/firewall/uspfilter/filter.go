package uspfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/forwarder"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/iface/netstack"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	layerTypeAll = 255

	// ipTCPHeaderMinSize represents minimum IP (20) + TCP (20) header size for MSS calculation
	ipTCPHeaderMinSize = 40
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

	// EnvForceUserspaceRouter forces userspace routing even if native routing is available.
	EnvForceUserspaceRouter = "NB_FORCE_USERSPACE_ROUTER"

	// EnvEnableLocalForwarding enables forwarding of local traffic to the native stack for internal (non-NetBird) interfaces.
	// Default off as it might be security risk because sockets listening on localhost only will become accessible.
	EnvEnableLocalForwarding = "NB_ENABLE_LOCAL_FORWARDING"

	// EnvEnableNetstackLocalForwarding is an alias for EnvEnableLocalForwarding.
	// In netstack mode, it enables forwarding of local traffic to the native stack for all interfaces.
	EnvEnableNetstackLocalForwarding = "NB_ENABLE_NETSTACK_LOCAL_FORWARDING"
)

var errNatNotSupported = errors.New("nat not supported with userspace firewall")

// RuleSet is a set of rules grouped by a string key
type RuleSet map[string]PeerRule

type RouteRules []*RouteRule

func (r RouteRules) Sort() {
	slices.SortStableFunc(r, func(a, b *RouteRule) int {
		// Deny rules come first
		if a.action == firewall.ActionDrop && b.action != firewall.ActionDrop {
			return -1
		}
		if a.action != firewall.ActionDrop && b.action == firewall.ActionDrop {
			return 1
		}
		return strings.Compare(a.id, b.id)
	})
}

// Manager userspace firewall manager
type Manager struct {
	outgoingRules     map[netip.Addr]RuleSet
	incomingDenyRules map[netip.Addr]RuleSet
	incomingRules     map[netip.Addr]RuleSet
	routeRules        RouteRules
	decoders          sync.Pool
	wgIface           common.IFaceMapper
	nativeFirewall    firewall.Manager

	mutex sync.RWMutex

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

	udpTracker  *conntrack.UDPTracker
	icmpTracker *conntrack.ICMPTracker
	tcpTracker  *conntrack.TCPTracker
	forwarder   atomic.Pointer[forwarder.Forwarder]
	logger      *nblog.Logger
	flowLogger  nftypes.FlowLogger

	blockRule firewall.Rule

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

	mtu             uint16
	mssClampValue   uint16
	mssClampEnabled bool
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
	parser  *gopacket.DecodingLayerParser

	dnatOrigPort uint16
}

// Create userspace firewall manager constructor
func Create(iface common.IFaceMapper, disableServerRoutes bool, flowLogger nftypes.FlowLogger, mtu uint16) (*Manager, error) {
	return create(iface, nil, disableServerRoutes, flowLogger, mtu)
}

func CreateWithNativeFirewall(iface common.IFaceMapper, nativeFirewall firewall.Manager, disableServerRoutes bool, flowLogger nftypes.FlowLogger, mtu uint16) (*Manager, error) {
	if nativeFirewall == nil {
		return nil, errors.New("native firewall is nil")
	}

	mgr, err := create(iface, nativeFirewall, disableServerRoutes, flowLogger, mtu)
	if err != nil {
		return nil, err
	}

	return mgr, nil
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

func create(iface common.IFaceMapper, nativeFirewall firewall.Manager, disableServerRoutes bool, flowLogger nftypes.FlowLogger, mtu uint16) (*Manager, error) {
	disableConntrack, enableLocalForwarding, disableMSSClamping := parseCreateEnv()

	m := &Manager{
		decoders: sync.Pool{
			New: func() any {
				d := &decoder{
					decoded: []gopacket.LayerType{},
				}
				d.parser = gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv4,
					&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
				)
				d.parser.IgnoreUnsupported = true
				return d
			},
		},
		nativeFirewall:      nativeFirewall,
		outgoingRules:       make(map[netip.Addr]RuleSet),
		incomingDenyRules:   make(map[netip.Addr]RuleSet),
		incomingRules:       make(map[netip.Addr]RuleSet),
		wgIface:             iface,
		localipmanager:      newLocalIPManager(),
		disableServerRoutes: disableServerRoutes,
		stateful:            !disableConntrack,
		logger:              nblog.NewFromLogrus(log.StandardLogger()),
		flowLogger:          flowLogger,
		netstack:            netstack.IsEnabled(),
		localForwarding:     enableLocalForwarding,
		dnatMappings:        make(map[netip.Addr]netip.Addr),
		portDNATRules:       []portDNATRule{},
		netstackServices:    make(map[serviceKey]struct{}),
		mtu:                 mtu,
	}
	m.routingEnabled.Store(false)

	if !disableMSSClamping {
		m.mssClampEnabled = true
		m.mssClampValue = mtu - ipTCPHeaderMinSize
	}
	if err := m.localipmanager.UpdateLocalIPs(iface); err != nil {
		return nil, fmt.Errorf("update local IPs: %w", err)
	}
	if disableConntrack {
		log.Info("conntrack is disabled")
	} else {
		m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout, m.logger, flowLogger)
		m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout, m.logger, flowLogger)
		m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout, m.logger, flowLogger)
	}
	if m.netstack && m.localForwarding {
		if err := m.initForwarder(); err != nil {
			log.Errorf("failed to initialize forwarder: %v", err)
		}
	}
	if err := iface.SetFilter(m); err != nil {
		return nil, fmt.Errorf("set filter: %w", err)
	}
	return m, nil
}

func (m *Manager) blockInvalidRouted(iface common.IFaceMapper) (firewall.Rule, error) {
	wgPrefix := iface.Address().Network
	log.Debugf("blocking invalid routed traffic for %s", wgPrefix)

	rule, err := m.addRouteFiltering(
		nil,
		[]netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
		firewall.Network{Prefix: wgPrefix},
		firewall.ProtocolALL,
		nil,
		nil,
		firewall.ActionDrop,
	)
	if err != nil {
		return nil, fmt.Errorf("block wg nte : %w", err)
	}

	// TODO: Block networks that we're a client of

	return rule, nil
}

func (m *Manager) determineRouting() error {
	var disableUspRouting, forceUserspaceRouter bool
	var err error
	if val := os.Getenv(EnvDisableUserspaceRouting); val != "" {
		disableUspRouting, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvDisableUserspaceRouting, err)
		}
	}
	if val := os.Getenv(EnvForceUserspaceRouter); val != "" {
		forceUserspaceRouter, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", EnvForceUserspaceRouter, err)
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

	case forceUserspaceRouter:
		m.routingEnabled.Store(true)
		m.nativeRouter.Store(false)

		log.Info("userspace routing is forced")

	case !m.netstack && m.nativeFirewall != nil:
		// if the OS supports routing natively, then we don't need to filter/route ourselves
		// netstack mode won't support native routing as there is no interface

		m.routingEnabled.Store(true)
		m.nativeRouter.Store(true)

		log.Info("native routing is enabled")

	default:
		m.routingEnabled.Store(true)
		m.nativeRouter.Store(false)

		log.Info("userspace routing enabled by default")
	}

	if m.routingEnabled.Load() && !m.nativeRouter.Load() {
		return m.initForwarder()
	}

	return nil
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

func (m *Manager) AddNatRule(pair firewall.RouterPair) error {
	if m.nativeRouter.Load() && m.nativeFirewall != nil {
		return m.nativeFirewall.AddNatRule(pair)
	}

	// userspace routed packets are always SNATed to the inbound direction
	// TODO: implement outbound SNAT
	return nil
}

// RemoveNatRule removes a routing firewall rule
func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	if m.nativeRouter.Load() && m.nativeFirewall != nil {
		return m.nativeFirewall.RemoveNatRule(pair)
	}
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
	_ string,
) ([]firewall.Rule, error) {
	// TODO: fix in upper layers
	i, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	i = i.Unmap()
	r := PeerRule{
		id:        uuid.New().String(),
		mgmtId:    id,
		ip:        i,
		ipLayer:   layers.LayerTypeIPv6,
		matchByIP: true,
		drop:      action == firewall.ActionDrop,
	}
	if i.Is4() {
		r.ipLayer = layers.LayerTypeIPv4
	}

	if s := r.ip.String(); s == "0.0.0.0" || s == "::" {
		r.matchByIP = false
	}

	r.sPort = sPort
	r.dPort = dPort

	r.protoLayer = protoToLayer(proto, r.ipLayer)

	m.mutex.Lock()
	var targetMap map[netip.Addr]RuleSet
	if r.drop {
		targetMap = m.incomingDenyRules
	} else {
		targetMap = m.incomingRules
	}

	if _, ok := targetMap[r.ip]; !ok {
		targetMap[r.ip] = make(RuleSet)
	}
	targetMap[r.ip][r.id] = r
	m.mutex.Unlock()
	return []firewall.Rule{&r}, nil
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

	return m.addRouteFiltering(id, sources, destination, proto, sPort, dPort, action)
}

func (m *Manager) addRouteFiltering(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	if m.nativeRouter.Load() && m.nativeFirewall != nil {
		return m.nativeFirewall.AddRouteFiltering(id, sources, destination, proto, sPort, dPort, action)
	}

	ruleID := uuid.New().String()

	rule := RouteRule{
		// TODO: consolidate these IDs
		id:         ruleID,
		mgmtId:     id,
		sources:    sources,
		dstSet:     destination.Set,
		protoLayer: protoToLayer(proto, layers.LayerTypeIPv4),
		srcPort:    sPort,
		dstPort:    dPort,
		action:     action,
	}
	if destination.IsPrefix() {
		rule.destinations = []netip.Prefix{destination.Prefix}
	}

	m.routeRules = append(m.routeRules, &rule)
	m.routeRules.Sort()

	return &rule, nil
}

func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.deleteRouteRule(rule)
}

func (m *Manager) deleteRouteRule(rule firewall.Rule) error {
	if m.nativeRouter.Load() && m.nativeFirewall != nil {
		return m.nativeFirewall.DeleteRouteRule(rule)
	}

	ruleID := rule.ID()
	idx := slices.IndexFunc(m.routeRules, func(r *RouteRule) bool {
		return r.id == ruleID
	})
	if idx < 0 {
		return fmt.Errorf("route rule not found: %s", ruleID)
	}

	m.routeRules = slices.Delete(m.routeRules, idx, idx+1)
	return nil
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	r, ok := rule.(*PeerRule)
	if !ok {
		return fmt.Errorf("delete rule: invalid rule type: %T", rule)
	}

	var sourceMap map[netip.Addr]RuleSet
	if r.drop {
		sourceMap = m.incomingDenyRules
	} else {
		sourceMap = m.incomingRules
	}

	if ruleset, ok := sourceMap[r.ip]; ok {
		if _, exists := ruleset[r.id]; !exists {
			return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
		}
		delete(ruleset, r.id)
		if len(ruleset) == 0 {
			delete(sourceMap, r.ip)
		}
	} else {
		return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
	}

	return nil
}

// SetLegacyManagement doesn't need to be implemented for this manager
func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	if m.nativeFirewall == nil {
		return nil
	}
	return m.nativeFirewall.SetLegacyManagement(isLegacy)
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

// UpdateSet updates the rule destinations associated with the given set
// by merging the existing prefixes with the new ones, then deduplicating.
func (m *Manager) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	if m.nativeRouter.Load() && m.nativeFirewall != nil {
		return m.nativeFirewall.UpdateSet(set, prefixes)
	}

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
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			destinations = append(destinations, prefix)
		}
	}

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

	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		return false
	}

	if len(d.decoded) < 2 {
		return false
	}

	srcIP, dstIP := m.extractIPs(d)
	if !srcIP.IsValid() {
		m.logger.Error1("Unknown network layer: %v", d.decoded[0])
		return false
	}

	switch d.decoded[1] {
	case layers.LayerTypeUDP:
		if m.udpHooksDrop(uint16(d.udp.DstPort), dstIP, packetData) {
			return true
		}
	case layers.LayerTypeTCP:
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
		return src, dst
	case layers.LayerTypeIPv6:
		src, _ := netip.AddrFromSlice(d.ip6.SrcIP)
		dst, _ := netip.AddrFromSlice(d.ip6.DstIP)
		return src, dst
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

	mssOptionIndex := -1
	var currentMSS uint16
	for i, opt := range d.tcp.Options {
		if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) == 2 {
			currentMSS = binary.BigEndian.Uint16(opt.OptionData)
			if currentMSS > m.mssClampValue {
				mssOptionIndex = i
				break
			}
		}
	}

	if mssOptionIndex == -1 {
		return false
	}

	ipHeaderSize := int(d.ip4.IHL) * 4
	if ipHeaderSize < 20 {
		return false
	}

	if !m.updateMSSOption(packetData, d, mssOptionIndex, ipHeaderSize) {
		return false
	}

	m.logger.Trace2("Clamped TCP MSS from %d to %d", currentMSS, m.mssClampValue)
	return true
}

func (m *Manager) updateMSSOption(packetData []byte, d *decoder, mssOptionIndex, ipHeaderSize int) bool {
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
	binary.BigEndian.PutUint16(packetData[mssValueOffset:mssValueOffset+2], m.mssClampValue)

	m.recalculateTCPChecksum(packetData, d, tcpHeaderStart)
	return true
}

func (m *Manager) recalculateTCPChecksum(packetData []byte, d *decoder, tcpHeaderStart int) {
	tcpLayer := packetData[tcpHeaderStart:]
	tcpLength := len(packetData) - tcpHeaderStart

	tcpLayer[16] = 0
	tcpLayer[17] = 0

	var pseudoSum uint32
	pseudoSum += uint32(d.ip4.SrcIP[0])<<8 | uint32(d.ip4.SrcIP[1])
	pseudoSum += uint32(d.ip4.SrcIP[2])<<8 | uint32(d.ip4.SrcIP[3])
	pseudoSum += uint32(d.ip4.DstIP[0])<<8 | uint32(d.ip4.DstIP[1])
	pseudoSum += uint32(d.ip4.DstIP[2])<<8 | uint32(d.ip4.DstIP[3])
	pseudoSum += uint32(d.ip4.Protocol)
	pseudoSum += uint32(tcpLength)

	var sum = pseudoSum
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
	}

	d.dnatOrigPort = 0
}

// udpHooksDrop checks if any UDP hooks should drop the packet
func (m *Manager) udpHooksDrop(dport uint16, dstIP netip.Addr, packetData []byte) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check specific destination IP first
	if rules, exists := m.outgoingRules[dstIP]; exists {
		for _, rule := range rules {
			if rule.udpHook != nil && portsMatch(rule.dPort, dport) {
				return rule.udpHook(packetData)
			}
		}
	}

	// Check IPv4 unspecified address
	if rules, exists := m.outgoingRules[netip.IPv4Unspecified()]; exists {
		for _, rule := range rules {
			if rule.udpHook != nil && portsMatch(rule.dPort, dport) {
				return rule.udpHook(packetData)
			}
		}
	}

	// Check IPv6 unspecified address
	if rules, exists := m.outgoingRules[netip.IPv6Unspecified()]; exists {
		for _, rule := range rules {
			if rule.udpHook != nil && portsMatch(rule.dPort, dport) {
				return rule.udpHook(packetData)
			}
		}
	}

	return false
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
		m.logger.Trace4("packet is a fragment: src=%v dst=%v id=%v flags=%v",
			srcIP, dstIP, d.ip4.Id, d.ip4.Flags)
		return false
	}

	// TODO: optimize port DNAT by caching matched rules in conntrack
	if translated := m.translateInboundPortDNAT(packetData, d, srcIP, dstIP); translated {
		// Re-decode after port DNAT translation to update port information
		if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
			m.logger.Error1("failed to re-decode packet after port DNAT: %v", err)
			return true
		}
		srcIP, dstIP = m.extractIPs(d)
	}

	if translated := m.translateInboundReverse(packetData, d); translated {
		// Re-decode after translation to get original addresses
		if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
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

		m.logger.Trace6("Dropping local packet (ACL denied): rule_id=%s proto=%v src=%s:%d dst=%s:%d",
			ruleID, pnum, srcIP, srcPort, dstIP, dstPort)

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
		m.logger.Trace2("Dropping routed packet (routing disabled): src=%s dst=%s",
			srcIP, dstIP)
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

		m.logger.Trace6("Dropping routed packet (ACL denied): rule_id=%s proto=%v src=%s:%d dst=%s:%d",
			ruleID, proto, srcIP, srcPort, dstIP, dstPort)

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
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		return nftypes.ICMP
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
	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		m.logger.Trace1("couldn't decode packet, err: %s", err)
		return false, false
	}

	l := len(d.decoded)

	// L3 and L4 are mandatory
	if l >= 2 {
		return true, false
	}

	// Fragments are also valid
	if l == 1 && d.decoded[0] == layers.LayerTypeIPv4 {
		ip4 := d.ip4
		if ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0 {
			return true, true
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

		// TODO: ICMPv6
	}

	return false
}

// isSpecialICMP returns true if the packet is a special ICMP packet that should be allowed
func (m *Manager) isSpecialICMP(d *decoder) bool {
	if d.decoded[1] != layers.LayerTypeICMPv4 {
		return false
	}

	icmpType := d.icmp4.TypeCode.Type()
	return icmpType == layers.ICMPv4TypeDestinationUnreachable ||
		icmpType == layers.ICMPv4TypeTimeExceeded
}

func (m *Manager) peerACLsBlock(srcIP netip.Addr, d *decoder, packetData []byte) ([]byte, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.isSpecialICMP(d) {
		return nil, false
	}

	if mgmtId, filter, ok := validateRule(srcIP, packetData, m.incomingDenyRules[srcIP], d); ok {
		return mgmtId, filter
	}

	if mgmtId, filter, ok := validateRule(srcIP, packetData, m.incomingRules[srcIP], d); ok {
		return mgmtId, filter
	}
	if mgmtId, filter, ok := validateRule(srcIP, packetData, m.incomingRules[netip.IPv4Unspecified()], d); ok {
		return mgmtId, filter
	}
	if mgmtId, filter, ok := validateRule(srcIP, packetData, m.incomingRules[netip.IPv6Unspecified()], d); ok {
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

func validateRule(ip netip.Addr, packetData []byte, rules map[string]PeerRule, d *decoder) ([]byte, bool, bool) {
	payloadLayer := d.decoded[1]

	for _, rule := range rules {
		if rule.matchByIP && ip.Compare(rule.ip) != 0 {
			continue
		}

		if rule.protoLayer == layerTypeAll {
			return rule.mgmtId, rule.drop, true
		}

		if payloadLayer != rule.protoLayer {
			continue
		}

		switch payloadLayer {
		case layers.LayerTypeTCP:
			if portsMatch(rule.sPort, uint16(d.tcp.SrcPort)) && portsMatch(rule.dPort, uint16(d.tcp.DstPort)) {
				return rule.mgmtId, rule.drop, true
			}
		case layers.LayerTypeUDP:
			// if rule has UDP hook (and if we are here we match this rule)
			// we ignore rule.drop and call this hook
			if rule.udpHook != nil {
				return rule.mgmtId, rule.udpHook(packetData), true
			}

			if portsMatch(rule.sPort, uint16(d.udp.SrcPort)) && portsMatch(rule.dPort, uint16(d.udp.DstPort)) {
				return rule.mgmtId, rule.drop, true
			}
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			return rule.mgmtId, rule.drop, true
		}
	}

	return nil, false, false
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
	// TODO: handle ipv6 vs ipv4 icmp rules
	if rule.protoLayer != layerTypeAll && rule.protoLayer != protoLayer {
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

// AddUDPPacketHook calls hook when UDP packet from given direction matched
//
// Hook function returns flag which indicates should be the matched package dropped or not
func (m *Manager) AddUDPPacketHook(in bool, ip netip.Addr, dPort uint16, hook func(packet []byte) bool) string {
	r := PeerRule{
		id:         uuid.New().String(),
		ip:         ip,
		protoLayer: layers.LayerTypeUDP,
		dPort:      &firewall.Port{Values: []uint16{dPort}},
		ipLayer:    layers.LayerTypeIPv6,
		udpHook:    hook,
	}

	if ip.Is4() {
		r.ipLayer = layers.LayerTypeIPv4
	}

	m.mutex.Lock()
	if in {
		// Incoming UDP hooks are stored in allow rules map
		if _, ok := m.incomingRules[r.ip]; !ok {
			m.incomingRules[r.ip] = make(map[string]PeerRule)
		}
		m.incomingRules[r.ip][r.id] = r
	} else {
		if _, ok := m.outgoingRules[r.ip]; !ok {
			m.outgoingRules[r.ip] = make(map[string]PeerRule)
		}
		m.outgoingRules[r.ip][r.id] = r
	}
	m.mutex.Unlock()

	return r.id
}

// RemovePacketHook removes packet hook by given ID
func (m *Manager) RemovePacketHook(hookID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check incoming hooks (stored in allow rules)
	for _, arr := range m.incomingRules {
		for _, r := range arr {
			if r.id == hookID {
				delete(arr, r.id)
				return nil
			}
		}
	}
	// Check outgoing hooks
	for _, arr := range m.outgoingRules {
		for _, r := range arr {
			if r.id == hookID {
				delete(arr, r.id)
				return nil
			}
		}
	}
	return fmt.Errorf("hook with given id not found")
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

	rule, err := m.blockInvalidRouted(m.wgIface)
	if err != nil {
		return fmt.Errorf("block invalid routed: %w", err)
	}

	m.blockRule = rule

	return nil
}

func (m *Manager) DisableRouting() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	fwder := m.forwarder.Load()
	if fwder == nil {
		return nil
	}

	m.routingEnabled.Store(false)
	m.nativeRouter.Store(false)

	// don't stop forwarder if in use by netstack
	if m.netstack && m.localForwarding {
		return nil
	}

	fwder.Stop()
	m.forwarder.Store(nil)

	log.Debug("forwarder stopped")

	if m.blockRule != nil {
		if err := m.deleteRouteRule(m.blockRule); err != nil {
			return fmt.Errorf("delete block rule: %w", err)
		}
		m.blockRule = nil
	}

	return nil
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
	if dstIP != m.wgIface.Address().IP {
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
