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

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFiltering(iface.PacketFilter) error
}

// Manager userspace firewall manager
type Manager struct {
	inputRules  []Rule
	outputRules []Rule
	rulesIndex  map[string]int
	wgNetwork   *net.IPNet

	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	mutex sync.RWMutex
}

// Create userspace firewall manager constructor
func Create(iface IFaceMapper) (*Manager, error) {
	m := &Manager{
		rulesIndex: make(map[string]int),
		decoded:    make([]gopacket.LayerType, 0, 20),
	}

	m.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,
		&m.ip4,
		&m.ip6,
	)
	m.parser.IgnoreUnsupported = true

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
	direction fw.Direction,
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
		// just use default 0 value for r.protoLayer
	}

	u.mutex.RLock()
	var p int
	if direction == fw.DirectionDst {
		u.outputRules = append(u.outputRules, r)
		p = len(u.outputRules) - 1
	} else {
		u.inputRules = append(u.inputRules, r)
		p = len(u.inputRules) - 1
	}
	u.rulesIndex[r.id] = p
	u.mutex.RUnlock()

	return &r, nil
}

// DeleteRule from the firewall by rule definition
func (u *Manager) DeleteRule(rule fw.Rule) error {
	u.mutex.RLock()
	defer u.mutex.RUnlock()

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
	if r.direction == fw.DirectionDst {
		u.outputRules = append(u.outputRules[:p], u.outputRules[p+1:]...)
		toUpdate = u.outputRules
	} else {
		u.inputRules = append(u.inputRules[:p], u.inputRules[p+1:]...)
		toUpdate = u.inputRules
	}

	for i := 0; i < len(toUpdate); i++ {
		u.rulesIndex[toUpdate[i].id] = i
	}

	return nil
}

// Reset firewall to the default state
func (u *Manager) Reset() error {
	u.mutex.RLock()
	defer u.mutex.RUnlock()

	u.inputRules = u.inputRules[:0]
	u.outputRules = u.outputRules[:0]
	u.rulesIndex = make(map[string]int)

	return nil
}

// DropInput packet filter
func (u *Manager) DropInput(packetData []byte) bool {
	return u.dropFilter(packetData, u.inputRules, false)
}

// DropOutput packet filter
func (u *Manager) DropOutput(packetData []byte) bool {
	return u.dropFilter(packetData, u.outputRules, true)
}

// dropFilter imlements same logic for booth direction of the traffic
func (u *Manager) dropFilter(packetData []byte, rules []Rule, isOutputPacket bool) bool {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if err := u.parser.DecodeLayers(packetData, &u.decoded); err != nil {
		return true
	}

	var ipDecoded gopacket.DecodingLayer
	switch u.decoded[0] {
	case layers.LayerTypeIPv4:
		if !u.wgNetwork.Contains(u.ip4.SrcIP) || !u.wgNetwork.Contains(u.ip4.DstIP) {
			return false
		}
		ipDecoded = &u.ip4
	case layers.LayerTypeIPv6:
		if !u.wgNetwork.Contains(u.ip6.SrcIP) || !u.wgNetwork.Contains(u.ip6.DstIP) {
			return false
		}
		ipDecoded = &u.ip6
	default:
		log.Errorf("unknown layer: %v", u.decoded[0])
		return true
	}

	payloadLayer := ipDecoded.NextLayerType().LayerTypes()[0]
	switch payloadLayer {
	case layers.LayerTypeTCP:
		if err := u.tcp.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding tcp packet: %v", err)
			return false
		}
	case layers.LayerTypeUDP:
		if err := u.udp.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding udp packet: %v", err)
			return false
		}
	case layers.LayerTypeICMPv4:
		if err := u.icmp4.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding icmpv4 packet: %v", err)
			return false
		}
	case layers.LayerTypeICMPv6:
		if err := u.icmp6.DecodeFromBytes(ipDecoded.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
			log.Errorf("error decoding icmpv6 packet: %v", err)
			return false
		}
	default:
		log.Errorf("layer is not allow: %v", payloadLayer)
		return true
	}

	// check if IP address match by IP
	for _, rule := range rules {
		switch u.decoded[0] {
		case layers.LayerTypeIPv4:
			if isOutputPacket {
				if !u.ip4.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !u.ip4.DstIP.Equal(rule.ip) {
					continue
				}
			}
		case layers.LayerTypeIPv6:
			if isOutputPacket {
				if !u.ip6.SrcIP.Equal(rule.ip) {
					continue
				}
			} else {
				if !u.ip6.DstIP.Equal(rule.ip) {
					continue
				}
			}
		}

		if rule.protoLayer != 0 && payloadLayer != rule.protoLayer {
			continue
		}

		switch payloadLayer {
		case 0:
			return false
		case layers.LayerTypeTCP:
			if rule.sPort != 0 && rule.sPort == uint16(u.tcp.DstPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort == uint16(u.tcp.SrcPort) {
				return rule.drop
			}
		case layers.LayerTypeUDP:
			if rule.sPort != 0 && rule.sPort == uint16(u.udp.DstPort) {
				return rule.drop
			}
			if rule.dPort != 0 && rule.dPort != uint16(u.udp.SrcPort) {
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
