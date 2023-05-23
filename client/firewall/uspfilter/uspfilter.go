package uspfilter

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

const layerTypeAll = 0

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFiltering(iface.PacketFilter) error
}

// Manager userspace firewall manager
type Manager struct {
	outgoingRules []Rule
	incomingRules []Rule
	rulesIndex    map[string]int
	wgNetwork     *net.IPNet
	decoders      sync.Pool

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
	m := &Manager{
		rulesIndex: make(map[string]int),
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
	}

	if err := iface.SetFiltering(m); err != nil {
		return nil, err
	}
	return m, nil
}

// AddFiltering rule to the firewall
//
// If comment argument is empty firewall manager should set
// rule ID as comment for the rule
func (m *Manager) AddFiltering(
	ip net.IP,
	proto fw.Protocol,
	sPort *fw.Port,
	dPort *fw.Port,
	direction fw.RuleDirection,
	action fw.Action,
	comment string,
) (fw.Rule, error) {
	r := Rule{
		id:        uuid.New().String(),
		ip:        ip,
		ipLayer:   layers.LayerTypeIPv6,
		direction: direction,
		drop:      action == fw.ActionDrop,
		comment:   comment,
	}
	if ipNormalized := ip.To4(); ipNormalized != nil {
		r.ipLayer = layers.LayerTypeIPv4
		r.ip = ipNormalized
	}

	if sPort != nil && len(sPort.Values) == 1 {
		r.sPort = uint16(sPort.Values[0])
	}

	if dPort != nil && len(dPort.Values) == 1 {
		r.dPort = uint16(dPort.Values[0])
	}

	switch proto {
	case fw.ProtocolTCP:
		r.protoLayer = layers.LayerTypeTCP
	case fw.ProtocolUDP:
		r.protoLayer = layers.LayerTypeUDP
	case fw.ProtocolICMP:
		r.protoLayer = layers.LayerTypeICMPv4
		if r.ipLayer == layers.LayerTypeIPv6 {
			r.protoLayer = layers.LayerTypeICMPv6
		}
	case fw.ProtocolALL:
		r.protoLayer = layerTypeAll
	}

	m.mutex.Lock()
	var p int
	if direction == fw.RuleDirectionIN {
		m.incomingRules = append(m.incomingRules, r)
		p = len(m.incomingRules) - 1
	} else {
		m.outgoingRules = append(m.outgoingRules, r)
		p = len(m.outgoingRules) - 1
	}
	m.rulesIndex[r.id] = p
	m.mutex.Unlock()

	return &r, nil
}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule fw.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("delete rule: invalid rule type: %T", rule)
	}

	p, ok := m.rulesIndex[r.id]
	if !ok {
		return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
	}
	delete(m.rulesIndex, r.id)

	var toUpdate []Rule
	if r.direction == fw.RuleDirectionIN {
		m.incomingRules = append(m.incomingRules[:p], m.incomingRules[p+1:]...)
		toUpdate = m.incomingRules
	} else {
		m.outgoingRules = append(m.outgoingRules[:p], m.outgoingRules[p+1:]...)
		toUpdate = m.outgoingRules
	}

	for i := 0; i < len(toUpdate); i++ {
		m.rulesIndex[toUpdate[i].id] = i
	}
	return nil
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.outgoingRules = m.outgoingRules[:0]
	m.incomingRules = m.incomingRules[:0]
	m.rulesIndex = make(map[string]int)

	return nil
}

// DropOutgoing filter outgoing packets
func (m *Manager) DropOutgoing(packetData []byte) bool {
	return m.dropFilter(packetData, m.outgoingRules, false)
}

// DropIncoming filter incoming packets
func (m *Manager) DropIncoming(packetData []byte) bool {
	return m.dropFilter(packetData, m.incomingRules, true)
}

// dropFilter imlements same logic for booth direction of the traffic
func (m *Manager) dropFilter(packetData []byte, rules []Rule, isIncomingPacket bool) bool {
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
	payloadLayer := d.decoded[1]

	// check if IP address match by IP
	for _, rule := range rules {
		switch ipLayer {
		case layers.LayerTypeIPv4:
			if isIncomingPacket {
				if !d.ip4.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !d.ip4.DstIP.Equal(rule.ip) {
					continue
				}
			}
		case layers.LayerTypeIPv6:
			if isIncomingPacket {
				if !d.ip6.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !d.ip6.DstIP.Equal(rule.ip) {
					continue
				}
			}
		}

		if rule.protoLayer == layerTypeAll {
			return rule.drop
		}

		if payloadLayer != rule.protoLayer {
			continue
		}

		switch payloadLayer {
		case layers.LayerTypeTCP:
			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop
			}
			if rule.sPort != 0 && rule.sPort == uint16(d.tcp.SrcPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort == uint16(d.tcp.DstPort) {
				return rule.drop
			}
		case layers.LayerTypeUDP:
			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop
			}
			if rule.sPort != 0 && rule.sPort == uint16(d.udp.SrcPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort == uint16(d.udp.DstPort) {
				return rule.drop
			}
			return rule.drop
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			return rule.drop
		}
	}

	// default policy is DROP ALL
	return true
}

// SetNetwork of the wireguard interface to which filtering applied
func (m *Manager) SetNetwork(network *net.IPNet) {
	m.wgNetwork = network
}
