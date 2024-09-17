package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

const layerTypeAll = 0

var (
	errRouteNotSupported = fmt.Errorf("route not supported with userspace firewall")
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFilter(iface.PacketFilter) error
	Address() iface.WGAddress
}

// RuleSet is a set of rules grouped by a string key
type RuleSet map[string]Rule

// Manager userspace firewall manager
type Manager struct {
	outgoingRules  map[string]RuleSet
	incomingRules  map[string]RuleSet
	wgNetwork      *net.IPNet
	decoders       sync.Pool
	wgIface        IFaceMapper
	nativeFirewall firewall.Manager

	mutex sync.RWMutex
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
	}

	if err := iface.SetFilter(m); err != nil {
		return nil, err
	}
	return m, nil
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
	r := Rule{
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

func (m *Manager) AddRouteFiltering(sources []netip.Prefix, destination netip.Prefix, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action) (firewall.Rule, error) {
	if m.nativeFirewall == nil {
		return nil, errRouteNotSupported
	}
	return m.nativeFirewall.AddRouteFiltering(sources, destination, proto, sPort, dPort, direction, action)
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
func (m *Manager) SetLegacyManagement(_ bool) error {
	return nil
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

// DropOutgoing filter outgoing packets
func (m *Manager) DropOutgoing(packetData []byte) bool {
	return m.dropFilter(packetData, m.outgoingRules, false)
}

// DropIncoming filter incoming packets
func (m *Manager) DropIncoming(packetData []byte) bool {
	return m.dropFilter(packetData, m.incomingRules, true)
}

// dropFilter implements same logic for booth direction of the traffic
func (m *Manager) dropFilter(packetData []byte, rules map[string]RuleSet, isIncomingPacket bool) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		log.Tracef("couldn't decode layer, err: %s", err)
		return true
	}

	if len(d.decoded) < 2 {
		log.Tracef("not enough levels in network packet")
		return true
	}

	ipLayer := d.decoded[0]

	switch ipLayer {
	case layers.LayerTypeIPv4:
		if !m.wgNetwork.Contains(d.ip4.SrcIP) || !m.wgNetwork.Contains(d.ip4.DstIP) {
			return false
		}
	case layers.LayerTypeIPv6:
		if !m.wgNetwork.Contains(d.ip6.SrcIP) || !m.wgNetwork.Contains(d.ip6.DstIP) {
			return false
		}
	default:
		log.Errorf("unknown layer: %v", d.decoded[0])
		return true
	}

	var ip net.IP
	switch ipLayer {
	case layers.LayerTypeIPv4:
		if isIncomingPacket {
			ip = d.ip4.SrcIP
		} else {
			ip = d.ip4.DstIP
		}
	case layers.LayerTypeIPv6:
		if isIncomingPacket {
			ip = d.ip6.SrcIP
		} else {
			ip = d.ip6.DstIP
		}
	}

	filter, ok := validateRule(ip, packetData, rules[ip.String()], d)
	if ok {
		return filter
	}
	filter, ok = validateRule(ip, packetData, rules["0.0.0.0"], d)
	if ok {
		return filter
	}
	filter, ok = validateRule(ip, packetData, rules["::"], d)
	if ok {
		return filter
	}

	// default policy is DROP ALL
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
