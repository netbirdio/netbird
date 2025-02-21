package uspfilter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

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
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const layerTypeAll = 0

const (
	// EnvDisableConntrack disables the stateful filter, replies to outbound traffic won't be allowed.
	EnvDisableConntrack = "NB_DISABLE_CONNTRACK"

	// EnvDisableUserspaceRouting disables userspace routing, to-be-routed packets will be dropped.
	EnvDisableUserspaceRouting = "NB_DISABLE_USERSPACE_ROUTING"

	// EnvForceUserspaceRouter forces userspace routing even if native routing is available.
	EnvForceUserspaceRouter = "NB_FORCE_USERSPACE_ROUTER"

	// EnvEnableNetstackLocalForwarding enables forwarding of local traffic to the native stack when running netstack
	// Leaving this on by default introduces a security risk as sockets on listening on localhost only will be accessible
	EnvEnableNetstackLocalForwarding = "NB_ENABLE_NETSTACK_LOCAL_FORWARDING"
)

var errNatNotSupported = errors.New("nat not supported with userspace firewall")

// RuleSet is a set of rules grouped by a string key
type RuleSet map[string]PeerRule

type RouteRules []RouteRule

func (r RouteRules) Sort() {
	slices.SortStableFunc(r, func(a, b RouteRule) int {
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
	// outgoingRules is used for hooks only
	outgoingRules map[string]RuleSet
	// incomingRules is used for filtering and hooks
	incomingRules  map[string]RuleSet
	routeRules     RouteRules
	wgNetwork      *net.IPNet
	decoders       sync.Pool
	wgIface        common.IFaceMapper
	nativeFirewall firewall.Manager

	mutex sync.RWMutex

	// indicates whether server routes are disabled
	disableServerRoutes bool
	// indicates whether we forward packets not destined for ourselves
	routingEnabled bool
	// indicates whether we leave forwarding and filtering to the native firewall
	nativeRouter bool
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
	forwarder   *forwarder.Forwarder
	logger      *nblog.Logger
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
}

// Create userspace firewall manager constructor
func Create(iface common.IFaceMapper, disableServerRoutes bool) (*Manager, error) {
	return create(iface, nil, disableServerRoutes)
}

func CreateWithNativeFirewall(iface common.IFaceMapper, nativeFirewall firewall.Manager, disableServerRoutes bool) (*Manager, error) {
	if nativeFirewall == nil {
		return nil, errors.New("native firewall is nil")
	}

	mgr, err := create(iface, nativeFirewall, disableServerRoutes)
	if err != nil {
		return nil, err
	}

	return mgr, nil
}

func parseCreateEnv() (bool, bool) {
	var disableConntrack, enableLocalForwarding bool
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
	}

	return disableConntrack, enableLocalForwarding
}

func create(iface common.IFaceMapper, nativeFirewall firewall.Manager, disableServerRoutes bool) (*Manager, error) {
	disableConntrack, enableLocalForwarding := parseCreateEnv()

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
		outgoingRules:       make(map[string]RuleSet),
		incomingRules:       make(map[string]RuleSet),
		wgIface:             iface,
		localipmanager:      newLocalIPManager(),
		disableServerRoutes: disableServerRoutes,
		routingEnabled:      false,
		stateful:            !disableConntrack,
		logger:              nblog.NewFromLogrus(log.StandardLogger()),
		netstack:            netstack.IsEnabled(),
		localForwarding:     enableLocalForwarding,
	}

	if err := m.localipmanager.UpdateLocalIPs(iface); err != nil {
		return nil, fmt.Errorf("update local IPs: %w", err)
	}

	if disableConntrack {
		log.Info("conntrack is disabled")
	} else {
		m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout, m.logger)
		m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout, m.logger)
		m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout, m.logger)
	}

	// netstack needs the forwarder for local traffic
	if m.netstack && m.localForwarding {
		if err := m.initForwarder(); err != nil {
			log.Errorf("failed to initialize forwarder: %v", err)
		}
	}

	if err := m.blockInvalidRouted(iface); err != nil {
		log.Errorf("failed to block invalid routed traffic: %v", err)
	}

	if err := iface.SetFilter(m); err != nil {
		return nil, fmt.Errorf("set filter: %w", err)
	}
	return m, nil
}

func (m *Manager) blockInvalidRouted(iface common.IFaceMapper) error {
	if m.forwarder == nil {
		return nil
	}
	wgPrefix, err := netip.ParsePrefix(iface.Address().Network.String())
	if err != nil {
		return fmt.Errorf("parse wireguard network: %w", err)
	}
	log.Debugf("blocking invalid routed traffic for %s", wgPrefix)

	if _, err := m.AddRouteFiltering(
		[]netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
		wgPrefix,
		firewall.ProtocolALL,
		nil,
		nil,
		firewall.ActionDrop,
	); err != nil {
		return fmt.Errorf("block wg nte : %w", err)
	}

	// TODO: Block networks that we're a client of

	return nil
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
		m.routingEnabled = false
		m.nativeRouter = false
		log.Info("userspace routing is disabled")

	case m.disableServerRoutes:
		//  if server routes are disabled we will let packets pass to the native stack
		m.routingEnabled = true
		m.nativeRouter = true

		log.Info("server routes are disabled")

	case forceUserspaceRouter:
		m.routingEnabled = true
		m.nativeRouter = false

		log.Info("userspace routing is forced")

	case !m.netstack && m.nativeFirewall != nil && m.nativeFirewall.IsServerRouteSupported():
		// if the OS supports routing natively, then we don't need to filter/route ourselves
		// netstack mode won't support native routing as there is no interface

		m.routingEnabled = true
		m.nativeRouter = true

		log.Info("native routing is enabled")

	default:
		m.routingEnabled = true
		m.nativeRouter = false

		log.Info("userspace routing enabled by default")
	}

	if m.routingEnabled && !m.nativeRouter {
		return m.initForwarder()
	}

	return nil
}

// initForwarder initializes the forwarder, it disables routing on errors
func (m *Manager) initForwarder() error {
	if m.forwarder != nil {
		return nil
	}

	// Only supported in userspace mode as we need to inject packets back into wireguard directly
	intf := m.wgIface.GetWGDevice()
	if intf == nil {
		m.routingEnabled = false
		return errors.New("forwarding not supported")
	}

	forwarder, err := forwarder.New(m.wgIface, m.logger, m.netstack)
	if err != nil {
		m.routingEnabled = false
		return fmt.Errorf("create forwarder: %w", err)
	}

	m.forwarder = forwarder

	log.Debug("forwarder initialized")

	return nil
}

func (m *Manager) Init(*statemanager.Manager) error {
	return nil
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) AddNatRule(pair firewall.RouterPair) error {
	if m.nativeRouter && m.nativeFirewall != nil {
		return m.nativeFirewall.AddNatRule(pair)
	}

	// userspace routed packets are always SNATed to the inbound direction
	// TODO: implement outbound SNAT
	return nil
}

// RemoveNatRule removes a routing firewall rule
func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	if m.nativeRouter && m.nativeFirewall != nil {
		return m.nativeFirewall.RemoveNatRule(pair)
	}
	return nil
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
	action firewall.Action,
	_ string,
	comment string,
) ([]firewall.Rule, error) {
	r := PeerRule{
		id:        uuid.New().String(),
		ip:        ip,
		ipLayer:   layers.LayerTypeIPv6,
		matchByIP: true,
		drop:      action == firewall.ActionDrop,
		comment:   comment,
	}
	if ipNormalized := ip.To4(); ipNormalized != nil {
		r.ipLayer = layers.LayerTypeIPv4
		r.ip = ipNormalized
	}

	if s := r.ip.String(); s == "0.0.0.0" || s == "::" {
		r.matchByIP = false
	}

	r.sPort = sPort
	r.dPort = dPort

	switch proto {
	case firewall.ProtocolTCP:
		r.protoLayer = layers.LayerTypeTCP
	case firewall.ProtocolUDP:
		r.protoLayer = layers.LayerTypeUDP
	case firewall.ProtocolICMP:
		r.protoLayer = layers.LayerTypeICMPv4
		if r.ipLayer == layers.LayerTypeIPv6 {
			r.protoLayer = layers.LayerTypeICMPv6
		}
	case firewall.ProtocolALL:
		r.protoLayer = layerTypeAll
	}

	m.mutex.Lock()
	if _, ok := m.incomingRules[r.ip.String()]; !ok {
		m.incomingRules[r.ip.String()] = make(RuleSet)
	}
	m.incomingRules[r.ip.String()][r.id] = r
	m.mutex.Unlock()
	return []firewall.Rule{&r}, nil
}

func (m *Manager) AddRouteFiltering(
	sources []netip.Prefix,
	destination netip.Prefix,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	if m.nativeRouter && m.nativeFirewall != nil {
		return m.nativeFirewall.AddRouteFiltering(sources, destination, proto, sPort, dPort, action)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	ruleID := uuid.New().String()
	rule := RouteRule{
		id:          ruleID,
		sources:     sources,
		destination: destination,
		proto:       proto,
		srcPort:     sPort,
		dstPort:     dPort,
		action:      action,
	}

	m.routeRules = append(m.routeRules, rule)
	m.routeRules.Sort()

	return &rule, nil
}

func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	if m.nativeRouter && m.nativeFirewall != nil {
		return m.nativeFirewall.DeleteRouteRule(rule)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	ruleID := rule.ID()
	idx := slices.IndexFunc(m.routeRules, func(r RouteRule) bool {
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

	if _, ok := m.incomingRules[r.ip.String()][r.id]; !ok {
		return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
	}
	delete(m.incomingRules[r.ip.String()], r.id)

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

// AddDNATRule adds a DNAT rule
func (m *Manager) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	if m.nativeFirewall == nil {
		return nil, errNatNotSupported
	}
	return m.nativeFirewall.AddDNATRule(rule)
}

// DeleteDNATRule deletes a DNAT rule
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	if m.nativeFirewall == nil {
		return errNatNotSupported
	}
	return m.nativeFirewall.DeleteDNATRule(rule)
}

// DropOutgoing filter outgoing packets
func (m *Manager) DropOutgoing(packetData []byte) bool {
	return m.processOutgoingHooks(packetData)
}

// DropIncoming filter incoming packets
func (m *Manager) DropIncoming(packetData []byte) bool {
	return m.dropFilter(packetData)
}

// UpdateLocalIPs updates the list of local IPs
func (m *Manager) UpdateLocalIPs() error {
	return m.localipmanager.UpdateLocalIPs(m.wgIface)
}

func (m *Manager) processOutgoingHooks(packetData []byte) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		return false
	}

	if len(d.decoded) < 2 {
		return false
	}

	srcIP, dstIP := m.extractIPs(d)
	if srcIP == nil {
		return false
	}

	// Track all protocols if stateful mode is enabled
	if m.stateful {
		switch d.decoded[1] {
		case layers.LayerTypeUDP:
			m.trackUDPOutbound(d, srcIP, dstIP)
		case layers.LayerTypeTCP:
			m.trackTCPOutbound(d, srcIP, dstIP)
		case layers.LayerTypeICMPv4:
			m.trackICMPOutbound(d, srcIP, dstIP)
		}
	}

	// Process UDP hooks even if stateful mode is disabled
	if d.decoded[1] == layers.LayerTypeUDP {
		return m.checkUDPHooks(d, dstIP, packetData)
	}

	return false
}

func (m *Manager) extractIPs(d *decoder) (srcIP, dstIP net.IP) {
	switch d.decoded[0] {
	case layers.LayerTypeIPv4:
		return d.ip4.SrcIP, d.ip4.DstIP
	case layers.LayerTypeIPv6:
		return d.ip6.SrcIP, d.ip6.DstIP
	default:
		return nil, nil
	}
}

func (m *Manager) trackTCPOutbound(d *decoder, srcIP, dstIP net.IP) {
	flags := getTCPFlags(&d.tcp)
	m.tcpTracker.TrackOutbound(
		srcIP,
		dstIP,
		uint16(d.tcp.SrcPort),
		uint16(d.tcp.DstPort),
		flags,
	)
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

func (m *Manager) trackUDPOutbound(d *decoder, srcIP, dstIP net.IP) {
	m.udpTracker.TrackOutbound(
		srcIP,
		dstIP,
		uint16(d.udp.SrcPort),
		uint16(d.udp.DstPort),
	)
}

func (m *Manager) checkUDPHooks(d *decoder, dstIP net.IP, packetData []byte) bool {
	for _, ipKey := range []string{dstIP.String(), "0.0.0.0", "::"} {
		if rules, exists := m.outgoingRules[ipKey]; exists {
			for _, rule := range rules {
				if rule.udpHook != nil && portsMatch(rule.dPort, uint16(d.udp.DstPort)) {
					return rule.udpHook(packetData)
				}
			}
		}
	}
	return false
}

func (m *Manager) trackICMPOutbound(d *decoder, srcIP, dstIP net.IP) {
	if d.icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
		m.icmpTracker.TrackOutbound(
			srcIP,
			dstIP,
			d.icmp4.Id,
			d.icmp4.Seq,
		)
	}
}

// dropFilter implements filtering logic for incoming packets.
// If it returns true, the packet should be dropped.
func (m *Manager) dropFilter(packetData []byte) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if !m.isValidPacket(d, packetData) {
		return true
	}

	srcIP, dstIP := m.extractIPs(d)
	if srcIP == nil {
		m.logger.Error("Unknown network layer: %v", d.decoded[0])
		return true
	}

	// For all inbound traffic, first check if it matches a tracked connection.
	// This must happen before any other filtering because the packets are statefully tracked.
	if m.stateful && m.isValidTrackedConnection(d, srcIP, dstIP) {
		return false
	}

	if m.localipmanager.IsLocalIP(dstIP) {
		return m.handleLocalTraffic(d, srcIP, dstIP, packetData)
	}

	return m.handleRoutedTraffic(d, srcIP, dstIP, packetData)
}

// handleLocalTraffic handles local traffic.
// If it returns true, the packet should be dropped.
func (m *Manager) handleLocalTraffic(d *decoder, srcIP, dstIP net.IP, packetData []byte) bool {
	if m.peerACLsBlock(srcIP, packetData, m.incomingRules, d) {
		m.logger.Trace("Dropping local packet (ACL denied): src=%s dst=%s",
			srcIP, dstIP)
		return true
	}

	// if running in netstack mode we need to pass this to the forwarder
	if m.netstack {
		return m.handleNetstackLocalTraffic(packetData)
	}

	return false
}

func (m *Manager) handleNetstackLocalTraffic(packetData []byte) bool {
	if !m.localForwarding {
		// pass to virtual tcp/ip stack to be picked up by listeners
		return false
	}

	if m.forwarder == nil {
		m.logger.Trace("Dropping local packet (forwarder not initialized)")
		return true
	}

	if err := m.forwarder.InjectIncomingPacket(packetData); err != nil {
		m.logger.Error("Failed to inject local packet: %v", err)
	}

	// don't process this packet further
	return true
}

// handleRoutedTraffic handles routed traffic.
// If it returns true, the packet should be dropped.
func (m *Manager) handleRoutedTraffic(d *decoder, srcIP, dstIP net.IP, packetData []byte) bool {
	// Drop if routing is disabled
	if !m.routingEnabled {
		m.logger.Trace("Dropping routed packet (routing disabled): src=%s dst=%s",
			srcIP, dstIP)
		return true
	}

	// Pass to native stack if native router is enabled or forced
	if m.nativeRouter {
		return false
	}

	proto := getProtocolFromPacket(d)
	srcPort, dstPort := getPortsFromPacket(d)

	if !m.routeACLsPass(srcIP, dstIP, proto, srcPort, dstPort) {
		m.logger.Trace("Dropping routed packet (ACL denied): src=%s:%d dst=%s:%d proto=%v",
			srcIP, srcPort, dstIP, dstPort, proto)
		return true
	}

	// Let forwarder handle the packet if it passed route ACLs
	if err := m.forwarder.InjectIncomingPacket(packetData); err != nil {
		m.logger.Error("Failed to inject incoming packet: %v", err)
	}

	// Forwarded packets shouldn't reach the native stack, hence they won't be visible in a packet capture
	return true
}

func getProtocolFromPacket(d *decoder) firewall.Protocol {
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return firewall.ProtocolTCP
	case layers.LayerTypeUDP:
		return firewall.ProtocolUDP
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		return firewall.ProtocolICMP
	default:
		return firewall.ProtocolALL
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

func (m *Manager) isValidPacket(d *decoder, packetData []byte) bool {
	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		m.logger.Trace("couldn't decode packet, err: %s", err)
		return false
	}

	if len(d.decoded) < 2 {
		m.logger.Trace("packet doesn't have network and transport layers")
		return false
	}
	return true
}

func (m *Manager) isValidTrackedConnection(d *decoder, srcIP, dstIP net.IP) bool {
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return m.tcpTracker.IsValidInbound(
			srcIP,
			dstIP,
			uint16(d.tcp.SrcPort),
			uint16(d.tcp.DstPort),
			getTCPFlags(&d.tcp),
		)

	case layers.LayerTypeUDP:
		return m.udpTracker.IsValidInbound(
			srcIP,
			dstIP,
			uint16(d.udp.SrcPort),
			uint16(d.udp.DstPort),
		)

	case layers.LayerTypeICMPv4:
		return m.icmpTracker.IsValidInbound(
			srcIP,
			dstIP,
			d.icmp4.Id,
			d.icmp4.Seq,
			d.icmp4.TypeCode.Type(),
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

func (m *Manager) peerACLsBlock(srcIP net.IP, packetData []byte, rules map[string]RuleSet, d *decoder) bool {
	if m.isSpecialICMP(d) {
		return false
	}

	if filter, ok := validateRule(srcIP, packetData, rules[srcIP.String()], d); ok {
		return filter
	}

	if filter, ok := validateRule(srcIP, packetData, rules["0.0.0.0"], d); ok {
		return filter
	}

	if filter, ok := validateRule(srcIP, packetData, rules["::"], d); ok {
		return filter
	}

	// Default policy: DROP ALL
	return true
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

func validateRule(ip net.IP, packetData []byte, rules map[string]PeerRule, d *decoder) (bool, bool) {
	payloadLayer := d.decoded[1]
	for _, rule := range rules {
		if rule.matchByIP && !ip.Equal(rule.ip) {
			continue
		}

		if rule.protoLayer == layerTypeAll {
			return rule.drop, true
		}

		if payloadLayer != rule.protoLayer {
			continue
		}

		switch payloadLayer {
		case layers.LayerTypeTCP:
			if portsMatch(rule.sPort, uint16(d.tcp.SrcPort)) && portsMatch(rule.dPort, uint16(d.tcp.DstPort)) {
				return rule.drop, true
			}
		case layers.LayerTypeUDP:
			// if rule has UDP hook (and if we are here we match this rule)
			// we ignore rule.drop and call this hook
			if rule.udpHook != nil {
				return rule.udpHook(packetData), true
			}

			if portsMatch(rule.sPort, uint16(d.udp.SrcPort)) && portsMatch(rule.dPort, uint16(d.udp.DstPort)) {
				return rule.drop, true
			}
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			return rule.drop, true
		}
	}
	return false, false
}

// routeACLsPass returns treu if the packet is allowed by the route ACLs
func (m *Manager) routeACLsPass(srcIP, dstIP net.IP, proto firewall.Protocol, srcPort, dstPort uint16) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	srcAddr := netip.AddrFrom4([4]byte(srcIP.To4()))
	dstAddr := netip.AddrFrom4([4]byte(dstIP.To4()))

	for _, rule := range m.routeRules {
		if m.ruleMatches(rule, srcAddr, dstAddr, proto, srcPort, dstPort) {
			return rule.action == firewall.ActionAccept
		}
	}
	return false
}

func (m *Manager) ruleMatches(rule RouteRule, srcAddr, dstAddr netip.Addr, proto firewall.Protocol, srcPort, dstPort uint16) bool {
	if !rule.destination.Contains(dstAddr) {
		return false
	}

	sourceMatched := false
	for _, src := range rule.sources {
		if src.Contains(srcAddr) {
			sourceMatched = true
			break
		}
	}
	if !sourceMatched {
		return false
	}

	if rule.proto != firewall.ProtocolALL && rule.proto != proto {
		return false
	}

	if proto == firewall.ProtocolTCP || proto == firewall.ProtocolUDP {
		if !portsMatch(rule.srcPort, srcPort) || !portsMatch(rule.dstPort, dstPort) {
			return false
		}
	}

	return true
}

// SetNetwork of the wireguard interface to which filtering applied
func (m *Manager) SetNetwork(network *net.IPNet) {
	m.wgNetwork = network
}

// AddUDPPacketHook calls hook when UDP packet from given direction matched
//
// Hook function returns flag which indicates should be the matched package dropped or not
func (m *Manager) AddUDPPacketHook(
	in bool, ip net.IP, dPort uint16, hook func([]byte) bool,
) string {
	r := PeerRule{
		id:         uuid.New().String(),
		ip:         ip,
		protoLayer: layers.LayerTypeUDP,
		dPort:      &firewall.Port{Values: []uint16{dPort}},
		ipLayer:    layers.LayerTypeIPv6,
		comment:    fmt.Sprintf("UDP Hook direction: %v, ip:%v, dport:%d", in, ip, dPort),
		udpHook:    hook,
	}

	if ip.To4() != nil {
		r.ipLayer = layers.LayerTypeIPv4
	}

	m.mutex.Lock()
	if in {
		if _, ok := m.incomingRules[r.ip.String()]; !ok {
			m.incomingRules[r.ip.String()] = make(map[string]PeerRule)
		}
		m.incomingRules[r.ip.String()][r.id] = r
	} else {
		if _, ok := m.outgoingRules[r.ip.String()]; !ok {
			m.outgoingRules[r.ip.String()] = make(map[string]PeerRule)
		}
		m.outgoingRules[r.ip.String()][r.id] = r
	}

	m.mutex.Unlock()

	return r.id
}

// RemovePacketHook removes packet hook by given ID
func (m *Manager) RemovePacketHook(hookID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, arr := range m.incomingRules {
		for _, r := range arr {
			if r.id == hookID {
				delete(arr, r.id)
				return nil
			}
		}
	}
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

	return m.determineRouting()
}

func (m *Manager) DisableRouting() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.forwarder == nil {
		return nil
	}

	m.routingEnabled = false
	m.nativeRouter = false

	// don't stop forwarder if in use by netstack
	if m.netstack && m.localForwarding {
		return nil
	}

	m.forwarder.Stop()
	m.forwarder = nil

	log.Debug("forwarder stopped")

	return nil
}
