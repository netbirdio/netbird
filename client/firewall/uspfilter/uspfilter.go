package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/forwarder"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const layerTypeAll = 0

const EnvDisableConntrack = "NB_DISABLE_CONNTRACK"

// TODO: Add env var to disable routing

var (
	errRouteNotSupported = fmt.Errorf("route not supported with userspace firewall")
)

// RuleSet is a set of rules grouped by a string key
type RuleSet map[string]PeerRule

// Manager userspace firewall manager
type Manager struct {
	outgoingRules  map[string]RuleSet
	incomingRules  map[string]RuleSet
	routeRules     map[string]RouteRule
	wgNetwork      *net.IPNet
	decoders       sync.Pool
	wgIface        common.IFaceMapper
	nativeFirewall firewall.Manager

	mutex sync.RWMutex

	routingEnabled bool

	stateful    bool
	udpTracker  *conntrack.UDPTracker
	icmpTracker *conntrack.ICMPTracker
	tcpTracker  *conntrack.TCPTracker
	forwarder   *forwarder.Forwarder
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
func Create(iface common.IFaceMapper) (*Manager, error) {
	return create(iface)
}

func CreateWithNativeFirewall(iface common.IFaceMapper, nativeFirewall firewall.Manager) (*Manager, error) {
	mgr, err := create(iface)
	if err != nil {
		return nil, err
	}

	mgr.nativeFirewall = nativeFirewall
	return mgr, nil
}

func create(iface common.IFaceMapper) (*Manager, error) {
	disableConntrack, _ := strconv.ParseBool(os.Getenv(EnvDisableConntrack))

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
		outgoingRules: make(map[string]RuleSet),
		incomingRules: make(map[string]RuleSet),
		routeRules:    make(map[string]RouteRule),
		wgIface:       iface,
		stateful:      !disableConntrack,
		// TODO: fix
		routingEnabled: true,
	}

	// Only initialize trackers if stateful mode is enabled
	if disableConntrack {
		log.Info("conntrack is disabled")
	} else {
		m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout)
		m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout)
		m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout)
	}

	intf := iface.GetWGDevice()
	if intf == nil {
		log.Info("forwarding not supported")
		// Only supported in userspace mode as we need to inject packets back into wireguard directly
		// TODO: Check if native firewall can do the job, in that case just forward everything (restores previous behavior)
		m.routingEnabled = false
	} else {
		var err error
		m.forwarder, err = forwarder.New(iface)
		if err != nil {
			log.Errorf("failed to create forwarder: %v", err)
			m.routingEnabled = false
		}
	}

	if err := iface.SetFilter(m); err != nil {
		return nil, fmt.Errorf("set filter: %w", err)
	}
	return m, nil
}

func (m *Manager) Init(*statemanager.Manager) error {
	return nil
}

func (m *Manager) IsServerRouteSupported() bool {
	if m.nativeFirewall == nil {
		return false
	} else {
		return true
	}
}

func (m *Manager) AddNatRule(pair firewall.RouterPair) error {
	if m.nativeFirewall == nil {
		return errRouteNotSupported
	}
	return m.nativeFirewall.AddNatRule(pair)
}

// RemoveNatRule removes a routing firewall rule
func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	if m.nativeFirewall == nil {
		return errRouteNotSupported
	}
	return m.nativeFirewall.RemoveNatRule(pair)
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
	r := PeerRule{
		id:        uuid.New().String(),
		ip:        ip,
		ipLayer:   layers.LayerTypeIPv6,
		matchByIP: true,
		direction: direction,
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

	if sPort != nil && len(sPort.Values) == 1 {
		r.sPort = uint16(sPort.Values[0])
	}

	if dPort != nil && len(dPort.Values) == 1 {
		r.dPort = uint16(dPort.Values[0])
	}

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
	if direction == firewall.RuleDirectionIN {
		if _, ok := m.incomingRules[r.ip.String()]; !ok {
			m.incomingRules[r.ip.String()] = make(RuleSet)
		}
		m.incomingRules[r.ip.String()][r.id] = r
	} else {
		if _, ok := m.outgoingRules[r.ip.String()]; !ok {
			m.outgoingRules[r.ip.String()] = make(RuleSet)
		}
		m.outgoingRules[r.ip.String()][r.id] = r
	}
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

	m.routeRules[ruleID] = rule

	return &rule, nil
}

func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	ruleID := rule.GetRuleID()
	if _, exists := m.routeRules[ruleID]; !exists {
		return fmt.Errorf("route rule not found: %s", ruleID)
	}

	delete(m.routeRules, ruleID)
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

	if r.direction == firewall.RuleDirectionIN {
		_, ok := m.incomingRules[r.ip.String()][r.id]
		if !ok {
			return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
		}
		delete(m.incomingRules[r.ip.String()], r.id)
	} else {
		_, ok := m.outgoingRules[r.ip.String()][r.id]
		if !ok {
			return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
		}
		delete(m.outgoingRules[r.ip.String()], r.id)
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

// DropOutgoing filter outgoing packets
func (m *Manager) DropOutgoing(packetData []byte) bool {
	return m.processOutgoingHooks(packetData)
}

// DropIncoming filter incoming packets
func (m *Manager) DropIncoming(packetData []byte) bool {
	return m.dropFilter(packetData, m.incomingRules)
}

func (m *Manager) isLocalIP(ip net.IP) bool {
	// TODO: add other interface IPs and keep track of them
	return ip.Equal(m.wgIface.Address().IP)
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
				if rule.udpHook != nil && (rule.dPort == 0 || rule.dPort == uint16(d.udp.DstPort)) {
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

// dropFilter implements filtering logic for incoming packets
func (m *Manager) dropFilter(packetData []byte, rules map[string]RuleSet) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if !m.isValidPacket(d, packetData) {
		log.Debugf("invalid packet: %v", d.decoded)
		return true
	}

	srcIP, dstIP := m.extractIPs(d)
	if srcIP == nil {
		log.Errorf("unknown layer: %v", d.decoded[0])
		return true
	}

	// Check if this is local or routed traffic
	isLocal := m.isLocalIP(dstIP)

	// For all inbound traffic, first check if it matches a tracked connection.
	// This must happen before any other filtering because the packets are statefully tracked.
	if m.stateful && m.isValidTrackedConnection(d, srcIP, dstIP) {
		return false
	}

	// Handle local traffic - apply peer ACLs
	if isLocal {
		return m.applyRules(srcIP, packetData, rules, d)
	}

	// Handle routed traffic
	// TODO: Handle replies for [routed network -> netbird peer], we don't need to start the forwarder here
	// We might need to apply NAT
	// Don't handle routing if not enabled
	if !m.routingEnabled {
		return true
	}

	// Get protocol and ports for route ACL check
	proto := getProtocolFromPacket(d)
	srcPort, dstPort := getPortsFromPacket(d)

	// Check route ACLs
	if !m.checkRouteACLs(srcIP, dstIP, proto, srcPort, dstPort) {
		return true
	}

	// Let forwarder handle the packet if it passed route ACLs
	err := m.forwarder.InjectIncomingPacket(packetData)
	if err != nil {
		log.Errorf("Failed to inject incoming packet: %v", err)
	}

	// Default: drop
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
		log.Tracef("couldn't decode layer, err: %s", err)
		return false
	}

	if len(d.decoded) < 2 {
		log.Tracef("not enough levels in network packet")
		return false
	}
	return true
}

func (m *Manager) isWireguardTraffic(srcIP, dstIP net.IP) bool {
	return m.wgNetwork.Contains(srcIP) && m.wgNetwork.Contains(dstIP)
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

func (m *Manager) applyRules(srcIP net.IP, packetData []byte, rules map[string]RuleSet, d *decoder) bool {
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
			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop, true
			}
			if rule.sPort != 0 && rule.sPort == uint16(d.tcp.SrcPort) {
				return rule.drop, true
			}
			if rule.dPort != 0 && rule.dPort == uint16(d.tcp.DstPort) {
				return rule.drop, true
			}
		case layers.LayerTypeUDP:
			// if rule has UDP hook (and if we are here we match this rule)
			// we ignore rule.drop and call this hook
			if rule.udpHook != nil {
				return rule.udpHook(packetData), true
			}

			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop, true
			}
			if rule.sPort != 0 && rule.sPort == uint16(d.udp.SrcPort) {
				return rule.drop, true
			}
			if rule.dPort != 0 && rule.dPort == uint16(d.udp.DstPort) {
				return rule.drop, true
			}
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			return rule.drop, true
		}
	}
	return false, false
}

func (m *Manager) checkRouteACLs(srcIP, dstIP net.IP, proto firewall.Protocol, srcPort, dstPort uint16) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	srcAddr, _ := netip.AddrFromSlice(srcIP)
	dstAddr, _ := netip.AddrFromSlice(dstIP)

	// Default deny if no rules match
	matched := false

	for _, rule := range m.routeRules {
		// Check destination
		if !rule.destination.Contains(dstAddr) {
			continue
		}

		// Check if source matches any source prefix
		sourceMatched := false
		for _, src := range rule.sources {
			if src.Contains(srcAddr) {
				sourceMatched = true
				break
			}
		}
		if !sourceMatched {
			continue
		}

		// Check protocol
		if rule.proto != firewall.ProtocolALL && rule.proto != proto {
			continue
		}

		// Check ports if specified
		if rule.srcPort != nil && rule.srcPort.Values[0] != int(srcPort) {
			continue
		}
		if rule.dstPort != nil && rule.dstPort.Values[0] != int(dstPort) {
			continue
		}

		matched = true
		if rule.action == firewall.ActionDrop {
			return false
		}
	}

	return matched
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
		dPort:      dPort,
		ipLayer:    layers.LayerTypeIPv6,
		direction:  firewall.RuleDirectionOUT,
		comment:    fmt.Sprintf("UDP Hook direction: %v, ip:%v, dport:%d", in, ip, dPort),
		udpHook:    hook,
	}

	if ip.To4() != nil {
		r.ipLayer = layers.LayerTypeIPv4
	}

	m.mutex.Lock()
	if in {
		r.direction = firewall.RuleDirectionIN
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
	for _, arr := range m.incomingRules {
		for _, r := range arr {
			if r.id == hookID {
				rule := r
				return m.DeletePeerRule(&rule)
			}
		}
	}
	for _, arr := range m.outgoingRules {
		for _, r := range arr {
			if r.id == hookID {
				rule := r
				return m.DeletePeerRule(&rule)
			}
		}
	}
	return fmt.Errorf("hook with given id not found")
}
