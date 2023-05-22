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

	decoded []gopacket.LayerType

	mutex sync.RWMutex
}

// Create userspace firewall manager constructor
func Create(iface IFaceMapper) (*Manager, error) {
	m := &Manager{
		rulesIndex: make(map[string]int),
		decoded:    make([]gopacket.LayerType, 0, 20),
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
func (u *Manager) AddFiltering(
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

	u.mutex.Lock()
	var p int
	if direction == fw.RuleDirectionIN {
		u.incomingRules = append(u.incomingRules, r)
		p = len(u.incomingRules) - 1
	} else {
		u.outgoingRules = append(u.outgoingRules, r)
		p = len(u.outgoingRules) - 1
	}
	u.rulesIndex[r.id] = p
	u.mutex.Unlock()

	return &r, nil
}

// DeleteRule from the firewall by rule definition
func (u *Manager) DeleteRule(rule fw.Rule) error {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	r, ok := rule.(*Rule)
	if !ok {
		return fmt.Errorf("delete rule: invalid rule type: %T", rule)
	}

	p, ok := u.rulesIndex[r.id]
	if !ok {
		return fmt.Errorf("delete rule: no rule with such id: %v", r.id)
	}
	delete(u.rulesIndex, r.id)

	var toUpdate []Rule
	if r.direction == fw.RuleDirectionIN {
		u.incomingRules = append(u.incomingRules[:p], u.incomingRules[p+1:]...)
		toUpdate = u.incomingRules
	} else {
		u.outgoingRules = append(u.outgoingRules[:p], u.outgoingRules[p+1:]...)
		toUpdate = u.outgoingRules
	}

	for i := 0; i < len(toUpdate); i++ {
		u.rulesIndex[toUpdate[i].id] = i
	}
	return nil
}

// Reset firewall to the default state
func (u *Manager) Reset() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	u.outgoingRules = u.outgoingRules[:0]
	u.incomingRules = u.incomingRules[:0]
	u.rulesIndex = make(map[string]int)

	return nil
}

// DropOutgoing filter outgoing packets
func (u *Manager) DropOutgoing(packetData []byte) bool {
	return u.dropFilter(packetData, u.outgoingRules, false)
}

// DropIncoming filter incoming packets
func (u *Manager) DropIncoming(packetData []byte) bool {
	return u.dropFilter(packetData, u.incomingRules, true)
}

// dropFilter imlements same logic for booth direction of the traffic
func (u *Manager) dropFilter(packetData []byte, rules []Rule, isIncomingPacket bool) bool {
	u.mutex.RLock()
	defer u.mutex.RUnlock()
	var (
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		udp   layers.UDP
		icmp4 layers.ICMPv4
		icmp6 layers.ICMPv6
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ip6)
	parser.IgnoreUnsupported = true

	u.decoded = u.decoded[:0]
	if err := parser.DecodeLayers(packetData, &u.decoded); err != nil {
		log.Tracef("couldn't decode layer, err: %s", err)
		return true
	} else if len(u.decoded) == 0 {
		log.Tracef("couldn't decode layer, err: %s", err)
		return true
	}

	var (
		ipDecoded gopacket.DecodingLayer
	)
	ipLayer := u.decoded[0]
	switch ipLayer {
	case layers.LayerTypeIPv4:
		if !u.wgNetwork.Contains(ip4.SrcIP) || !u.wgNetwork.Contains(ip4.DstIP) {
			return false
		}
		ipDecoded = &ip4
	case layers.LayerTypeIPv6:
		if !u.wgNetwork.Contains(ip6.SrcIP) || !u.wgNetwork.Contains(ip6.DstIP) {
			return false
		}
		ipDecoded = &ip6
	default:
		log.Errorf("unknown layer: %v", u.decoded[0])
		return true
	}

	payloadLayer := ipDecoded.NextLayerType().LayerTypes()[0]
	switch payloadLayer {
	case layers.LayerTypeTCP:
		if err := tcp.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding tcp packet: %v", err)
			return false
		}
	case layers.LayerTypeUDP:
		if err := udp.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding udp packet: %v", err)
			return false
		}
	case layers.LayerTypeICMPv4:
		if err := icmp4.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding icmpv4 packet: %v", err)
			return false
		}
	case layers.LayerTypeICMPv6:
		if err := icmp6.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding icmpv6 packet: %v", err)
			return false
		}
	default:
		log.Errorf("layer is not allowed: %v", payloadLayer)
		return true
	}

	// check if IP address match by IP
	for _, rule := range rules {
		switch ipLayer {
		case layers.LayerTypeIPv4:
			if isIncomingPacket {
				if !ip4.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !ip4.DstIP.Equal(rule.ip) {
					continue
				}
			}
		case layers.LayerTypeIPv6:
			if isIncomingPacket {
				if !ip6.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !ip6.DstIP.Equal(rule.ip) {
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
		case 0:
			return false
		case layers.LayerTypeTCP:
			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop
			}
			if rule.sPort != 0 && rule.sPort == uint16(tcp.SrcPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort == uint16(tcp.DstPort) {
				return rule.drop
			}
		case layers.LayerTypeUDP:
			if rule.sPort == 0 && rule.dPort == 0 {
				return rule.drop
			}
			if rule.sPort != 0 && rule.sPort == uint16(udp.SrcPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort == uint16(udp.DstPort) {
				return rule.drop
			}
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			return rule.drop
		}
	}

	// default policy is DROP ALL
	return true
}

// SetNetwork of the wireguard interface to which filtering applied
func (u *Manager) SetNetwork(network *net.IPNet) {
	u.wgNetwork = network
}
