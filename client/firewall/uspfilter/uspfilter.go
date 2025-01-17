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
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const layerTypeAll = 0

const EnvDisableConntrack = "NB_DISABLE_CONNTRACK"

var (
	errRouteNotSupported = fmt.Errorf("route not supported with userspace firewall")
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFilter(device.PacketFilter) error
	Address() iface.WGAddress
}

// RuleSet is a set of rules grouped by a string key
type RuleSet map[string]Rule

// Manager userspace firewall manager
type Manager struct {
	// outgoingRules is used for hooks only
	outgoingRules map[string]RuleSet
	// incomingRules is used for filtering and hooks
	incomingRules  map[string]RuleSet
	wgNetwork      *net.IPNet
	decoders       sync.Pool
	wgIface        IFaceMapper
	nativeFirewall firewall.Manager

	mutex sync.RWMutex

	stateful    bool
	udpTracker  *conntrack.UDPTracker
	icmpTracker *conntrack.ICMPTracker
	tcpTracker  *conntrack.TCPTracker
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
func Create(iface IFaceMapper) (*Manager, error) {
	return create(iface)
}

func CreateWithNativeFirewall(iface IFaceMapper, nativeFirewall firewall.Manager) (*Manager, error) {
	mgr, err := create(iface)
	if err != nil {
		return nil, err
	}

	mgr.nativeFirewall = nativeFirewall
	return mgr, nil
}

func create(iface IFaceMapper) (*Manager, error) {
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
		wgIface:       iface,
		stateful:      !disableConntrack,
	}

	// Only initialize trackers if stateful mode is enabled
	if disableConntrack {
		log.Info("conntrack is disabled")
	} else {
		m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout)
		m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout)
		m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout)
	}

	if err := iface.SetFilter(m); err != nil {
		return nil, err
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
	action firewall.Action,
	_ string,
	comment string,
) ([]firewall.Rule, error) {
	r := Rule{
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
	if _, ok := m.incomingRules[r.ip.String()]; !ok {
		m.incomingRules[r.ip.String()] = make(RuleSet)
	}
	m.incomingRules[r.ip.String()][r.id] = r
	m.mutex.Unlock()
	return []firewall.Rule{&r}, nil
}

func (m *Manager) AddRouteFiltering(sources []netip.Prefix, destination netip.Prefix, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, action firewall.Action) (firewall.Rule, error) {
	if m.nativeFirewall == nil {
		return nil, errRouteNotSupported
	}
	return m.nativeFirewall.AddRouteFiltering(sources, destination, proto, sPort, dPort, action)
}

func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	if m.nativeFirewall == nil {
		return errRouteNotSupported
	}
	return m.nativeFirewall.DeleteRouteRule(rule)
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	r, ok := rule.(*Rule)
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

// DropOutgoing filter outgoing packets
func (m *Manager) DropOutgoing(packetData []byte) bool {
	return m.processOutgoingHooks(packetData)
}

// DropIncoming filter incoming packets
func (m *Manager) DropIncoming(packetData []byte) bool {
	return m.dropFilter(packetData, m.incomingRules)
}

// processOutgoingHooks processes UDP hooks for outgoing packets and tracks TCP/UDP/ICMP
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

	// Always process UDP hooks
	if d.decoded[1] == layers.LayerTypeUDP {
		// Track UDP state only if enabled
		if m.stateful {
			m.trackUDPOutbound(d, srcIP, dstIP)
		}
		return m.checkUDPHooks(d, dstIP, packetData)
	}

	// Track other protocols only if stateful mode is enabled
	if m.stateful {
		switch d.decoded[1] {
		case layers.LayerTypeTCP:
			m.trackTCPOutbound(d, srcIP, dstIP)
		case layers.LayerTypeICMPv4:
			m.trackICMPOutbound(d, srcIP, dstIP)
		}
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
	// TODO: Disable router if --disable-server-router is set

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if !m.isValidPacket(d, packetData) {
		return true
	}

	srcIP, dstIP := m.extractIPs(d)
	if srcIP == nil {
		log.Errorf("unknown layer: %v", d.decoded[0])
		return true
	}

	if !m.isWireguardTraffic(srcIP, dstIP) {
		return false
	}

	// Check connection state only if enabled
	if m.stateful && m.isValidTrackedConnection(d, srcIP, dstIP) {
		return false
	}

	return m.applyRules(srcIP, packetData, rules, d)
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

func validateRule(ip net.IP, packetData []byte, rules map[string]Rule, d *decoder) (bool, bool) {
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
	r := Rule{
		id:         uuid.New().String(),
		ip:         ip,
		protoLayer: layers.LayerTypeUDP,
		dPort:      dPort,
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
			m.incomingRules[r.ip.String()] = make(map[string]Rule)
		}
		m.incomingRules[r.ip.String()][r.id] = r
	} else {
		if _, ok := m.outgoingRules[r.ip.String()]; !ok {
			m.outgoingRules[r.ip.String()] = make(map[string]Rule)
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
