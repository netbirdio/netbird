package uspfilter

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

// Manager userspace firewall manager
type Manager struct {
	inputRules  []Rule
	outputRules []Rule
	rulesIndex  map[string]int

	mutex sync.RWMutex
}

// New userspace firewall manager constructor
func Create(iface *iface.WGIface) (*Manager, error) {
	m := &Manager{
		rulesIndex: make(map[string]int),
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
	port *fw.Port,
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
	if port != nil && len(port.Values) == 1 {
		r.port = uint16(port.Values[0])
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
	}

	u.mutex.RLock()
	var p int
	if direction == fw.DirectionDst {
		u.outputRules = append(u.outputRules, r)
		p = len(u.outputRules) - 1
	} else {
		u.inputRules = append(u.inputRules, r)
		p = len(u.inputRules)
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

	var toUpdate []Rule
	if r.direction == fw.DirectionDst {
		u.inputRules = append(u.inputRules[:p], u.inputRules[p+1:]...)
		toUpdate = u.inputRules
	} else {
		u.outputRules = append(u.outputRules[:p], u.outputRules[p+1:]...)
		toUpdate = u.outputRules
	}
	for i := p; i < len(toUpdate); i++ {
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
func (u *Manager) DropInput(packet gopacket.Packet) bool {
	return u.dropFilter(packet, u.inputRules, false)
}

// DropOutput packet filter
func (u *Manager) DropOutput(packet gopacket.Packet) bool {
	return u.dropFilter(packet, u.outputRules, true)
}

// dropFilter imlements same logic for booth direction of the traffic
func (u *Manager) dropFilter(packet gopacket.Packet, rules []Rule, isInputPacket bool) bool {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	// check if IP address match by IP
	for _, rule := range rules {
		if layer := packet.Layer(rule.ipLayer); layer != nil {
			switch ip := layer.(type) {
			case *layers.IPv4:
				if isInputPacket {
					if !ip.SrcIP.Equal(rule.ip) {
						continue
					}
				} else {
					if !ip.DstIP.Equal(rule.ip) {
						continue
					}
				}
			case *layers.IPv6:
				if isInputPacket {
					if !bytes.Equal(ip.SrcIP, rule.ip) {
						continue
					}
				} else {
					if !bytes.Equal(ip.DstIP, rule.ip) {
						continue
					}
				}
			}
		}

		if rule.protoLayer != 0 {
			// Check if the packet is TCP type and the destination port is 53
			if layer := packet.Layer(rule.protoLayer); layer != nil {
				if rule.port != 0 {
					switch protocol := layer.(type) {
					case *layers.TCP:
						if rule.port == uint16(protocol.DstPort) {
							return rule.drop
						}
					case *layers.UDP:
						if rule.port == uint16(protocol.DstPort) {
							return rule.drop
						}
					case *layers.ICMPv4, *layers.ICMPv6:
						return rule.drop
					}
					// port is defined and protocol matched but we don't know how to work
					// with this type of the protocol, so the best option here is to log
					// but to be more secure let's drop it
					return true
				}
				return rule.drop
			}
		} else {
			return false
		}
	}

	// default policy is DROP ALL
	return true
}
