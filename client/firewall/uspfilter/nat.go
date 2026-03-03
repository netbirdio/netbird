package uspfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

var ErrIPv4Only = errors.New("only IPv4 is supported for DNAT")

var (
	errInvalidIPHeaderLength = errors.New("invalid IP header length")
)

const (
	// Port offsets in TCP/UDP headers
	sourcePortOffset      = 0
	destinationPortOffset = 2

	// IP address offsets in IPv4 header
	sourceIPOffset      = 12
	destinationIPOffset = 16
)

// ipv4Checksum calculates IPv4 header checksum.
func ipv4Checksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	var sum1, sum2 uint32

	// Parallel processing - unroll and compute two sums simultaneously
	sum1 += uint32(binary.BigEndian.Uint16(header[0:2]))
	sum2 += uint32(binary.BigEndian.Uint16(header[2:4]))
	sum1 += uint32(binary.BigEndian.Uint16(header[4:6]))
	sum2 += uint32(binary.BigEndian.Uint16(header[6:8]))
	sum1 += uint32(binary.BigEndian.Uint16(header[8:10]))
	// Skip checksum field at [10:12]
	sum2 += uint32(binary.BigEndian.Uint16(header[12:14]))
	sum1 += uint32(binary.BigEndian.Uint16(header[14:16]))
	sum2 += uint32(binary.BigEndian.Uint16(header[16:18]))
	sum1 += uint32(binary.BigEndian.Uint16(header[18:20]))

	sum := sum1 + sum2

	// Handle remaining bytes for headers > 20 bytes
	for i := 20; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}

	// Optimized carry fold - single iteration handles most cases
	sum = (sum & 0xFFFF) + (sum >> 16)
	if sum > 0xFFFF {
		sum++
	}

	return ^uint16(sum)
}

// icmpChecksum calculates ICMP checksum.
func icmpChecksum(data []byte) uint16 {
	var sum1, sum2, sum3, sum4 uint32
	i := 0

	// Process 16 bytes at once with 4 parallel accumulators
	for i <= len(data)-16 {
		sum1 += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		sum2 += uint32(binary.BigEndian.Uint16(data[i+2 : i+4]))
		sum3 += uint32(binary.BigEndian.Uint16(data[i+4 : i+6]))
		sum4 += uint32(binary.BigEndian.Uint16(data[i+6 : i+8]))
		sum1 += uint32(binary.BigEndian.Uint16(data[i+8 : i+10]))
		sum2 += uint32(binary.BigEndian.Uint16(data[i+10 : i+12]))
		sum3 += uint32(binary.BigEndian.Uint16(data[i+12 : i+14]))
		sum4 += uint32(binary.BigEndian.Uint16(data[i+14 : i+16]))
		i += 16
	}

	sum := sum1 + sum2 + sum3 + sum4

	// Handle remaining bytes
	for i < len(data)-1 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	sum = (sum & 0xFFFF) + (sum >> 16)
	if sum > 0xFFFF {
		sum++
	}

	return ^uint16(sum)
}

// biDNATMap maintains bidirectional DNAT mappings.
type biDNATMap struct {
	forward map[netip.Addr]netip.Addr
	reverse map[netip.Addr]netip.Addr
}

// portDNATRule represents a port-specific DNAT rule.
type portDNATRule struct {
	protocol   gopacket.LayerType
	origPort   uint16
	targetPort uint16
	targetIP   netip.Addr
}

// newBiDNATMap creates a new bidirectional DNAT mapping structure.
func newBiDNATMap() *biDNATMap {
	return &biDNATMap{
		forward: make(map[netip.Addr]netip.Addr),
		reverse: make(map[netip.Addr]netip.Addr),
	}
}

// set adds a bidirectional DNAT mapping between original and translated addresses.
func (b *biDNATMap) set(original, translated netip.Addr) {
	b.forward[original] = translated
	b.reverse[translated] = original
}

// delete removes a bidirectional DNAT mapping for the given original address.
func (b *biDNATMap) delete(original netip.Addr) {
	if translated, exists := b.forward[original]; exists {
		delete(b.forward, original)
		delete(b.reverse, translated)
	}
}

// getTranslated returns the translated address for a given original address.
func (b *biDNATMap) getTranslated(original netip.Addr) (netip.Addr, bool) {
	translated, exists := b.forward[original]
	return translated, exists
}

// getOriginal returns the original address for a given translated address.
func (b *biDNATMap) getOriginal(translated netip.Addr) (netip.Addr, bool) {
	original, exists := b.reverse[translated]
	return original, exists
}

// AddInternalDNATMapping adds a 1:1 IP address mapping for internal DNAT translation.
func (m *Manager) AddInternalDNATMapping(originalAddr, translatedAddr netip.Addr) error {
	if !originalAddr.IsValid() {
		return fmt.Errorf("invalid original IP address")
	}
	if !translatedAddr.IsValid() {
		return fmt.Errorf("invalid translated IP address")
	}

	if m.localipmanager.IsLocalIP(translatedAddr) {
		return fmt.Errorf("cannot map to local IP: %s", translatedAddr)
	}

	m.dnatMutex.Lock()
	defer m.dnatMutex.Unlock()

	if m.dnatMappings == nil || m.dnatBiMap == nil {
		m.dnatMappings = make(map[netip.Addr]netip.Addr)
		m.dnatBiMap = newBiDNATMap()
	}

	m.dnatMappings[originalAddr] = translatedAddr
	m.dnatBiMap.set(originalAddr, translatedAddr)

	if len(m.dnatMappings) == 1 {
		m.dnatEnabled.Store(true)
	}

	return nil
}

// RemoveInternalDNATMapping removes a 1:1 IP address mapping.
func (m *Manager) RemoveInternalDNATMapping(originalAddr netip.Addr) error {
	m.dnatMutex.Lock()
	defer m.dnatMutex.Unlock()

	if _, exists := m.dnatMappings[originalAddr]; !exists {
		return fmt.Errorf("mapping not found for: %s", originalAddr)
	}

	delete(m.dnatMappings, originalAddr)
	m.dnatBiMap.delete(originalAddr)
	if len(m.dnatMappings) == 0 {
		m.dnatEnabled.Store(false)
	}

	return nil
}

// getDNATTranslation returns the translated address if a mapping exists.
func (m *Manager) getDNATTranslation(addr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return addr, false
	}

	m.dnatMutex.RLock()
	translated, exists := m.dnatBiMap.getTranslated(addr)
	m.dnatMutex.RUnlock()
	return translated, exists
}

// findReverseDNATMapping finds original address for return traffic.
func (m *Manager) findReverseDNATMapping(translatedAddr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return translatedAddr, false
	}

	m.dnatMutex.RLock()
	original, exists := m.dnatBiMap.getOriginal(translatedAddr)
	m.dnatMutex.RUnlock()
	return original, exists
}

// translateOutboundDNAT applies DNAT translation to outbound packets.
func (m *Manager) translateOutboundDNAT(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})

	translatedIP, exists := m.getDNATTranslation(dstIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketIP(packetData, d, translatedIP, destinationIPOffset); err != nil {
		m.logger.Error1("failed to rewrite packet destination: %v", err)
		return false
	}

	m.logger.Trace2("DNAT: %s -> %s", dstIP, translatedIP)
	return true
}

// translateInboundReverse applies reverse DNAT to inbound return traffic.
func (m *Manager) translateInboundReverse(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})

	originalIP, exists := m.findReverseDNATMapping(srcIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketIP(packetData, d, originalIP, sourceIPOffset); err != nil {
		m.logger.Error1("failed to rewrite packet source: %v", err)
		return false
	}

	m.logger.Trace2("Reverse DNAT: %s -> %s", srcIP, originalIP)
	return true
}

// rewritePacketIP replaces an IP address (source or destination) in the packet and updates checksums.
func (m *Manager) rewritePacketIP(packetData []byte, d *decoder, newIP netip.Addr, ipOffset int) error {
	if !newIP.Is4() {
		return ErrIPv4Only
	}

	var oldIP [4]byte
	copy(oldIP[:], packetData[ipOffset:ipOffset+4])
	newIPBytes := newIP.As4()

	copy(packetData[ipOffset:ipOffset+4], newIPBytes[:])

	ipHeaderLen := int(d.ip4.IHL) * 4
	if ipHeaderLen < 20 || ipHeaderLen > len(packetData) {
		return errInvalidIPHeaderLength
	}

	binary.BigEndian.PutUint16(packetData[10:12], 0)
	ipChecksum := ipv4Checksum(packetData[:ipHeaderLen])
	binary.BigEndian.PutUint16(packetData[10:12], ipChecksum)

	if len(d.decoded) > 1 {
		switch d.decoded[1] {
		case layers.LayerTypeTCP:
			m.updateTCPChecksum(packetData, ipHeaderLen, oldIP[:], newIPBytes[:])
		case layers.LayerTypeUDP:
			m.updateUDPChecksum(packetData, ipHeaderLen, oldIP[:], newIPBytes[:])
		case layers.LayerTypeICMPv4:
			m.updateICMPChecksum(packetData, ipHeaderLen)
		}
	}

	return nil
}

// updateTCPChecksum updates TCP checksum after IP address change per RFC 1624.
func (m *Manager) updateTCPChecksum(packetData []byte, ipHeaderLen int, oldIP, newIP []byte) {
	tcpStart := ipHeaderLen
	if len(packetData) < tcpStart+18 {
		return
	}

	checksumOffset := tcpStart + 16
	oldChecksum := binary.BigEndian.Uint16(packetData[checksumOffset : checksumOffset+2])
	newChecksum := incrementalUpdate(oldChecksum, oldIP, newIP)
	binary.BigEndian.PutUint16(packetData[checksumOffset:checksumOffset+2], newChecksum)
}

// updateUDPChecksum updates UDP checksum after IP address change per RFC 1624.
func (m *Manager) updateUDPChecksum(packetData []byte, ipHeaderLen int, oldIP, newIP []byte) {
	udpStart := ipHeaderLen
	if len(packetData) < udpStart+8 {
		return
	}

	checksumOffset := udpStart + 6
	oldChecksum := binary.BigEndian.Uint16(packetData[checksumOffset : checksumOffset+2])

	if oldChecksum == 0 {
		return
	}

	newChecksum := incrementalUpdate(oldChecksum, oldIP, newIP)
	binary.BigEndian.PutUint16(packetData[checksumOffset:checksumOffset+2], newChecksum)
}

// updateICMPChecksum recalculates ICMP checksum after packet modification.
func (m *Manager) updateICMPChecksum(packetData []byte, ipHeaderLen int) {
	icmpStart := ipHeaderLen
	if len(packetData) < icmpStart+8 {
		return
	}

	icmpData := packetData[icmpStart:]
	binary.BigEndian.PutUint16(icmpData[2:4], 0)
	checksum := icmpChecksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], checksum)
}

// incrementalUpdate performs incremental checksum update per RFC 1624.
func incrementalUpdate(oldChecksum uint16, oldBytes, newBytes []byte) uint16 {
	sum := uint32(^oldChecksum)

	// Fast path for IPv4 addresses (4 bytes) - most common case
	if len(oldBytes) == 4 && len(newBytes) == 4 {
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[0:2]))
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[2:4])) //nolint:gosec // length checked above
		sum += uint32(binary.BigEndian.Uint16(newBytes[0:2]))
		sum += uint32(binary.BigEndian.Uint16(newBytes[2:4])) //nolint:gosec // length checked above
	} else {
		// Fallback for other lengths
		for i := 0; i < len(oldBytes)-1; i += 2 {
			sum += uint32(^binary.BigEndian.Uint16(oldBytes[i : i+2]))
		}
		if len(oldBytes)%2 == 1 {
			sum += uint32(^oldBytes[len(oldBytes)-1]) << 8
		}

		for i := 0; i < len(newBytes)-1; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(newBytes[i : i+2]))
		}
		if len(newBytes)%2 == 1 {
			sum += uint32(newBytes[len(newBytes)-1]) << 8
		}
	}

	sum = (sum & 0xFFFF) + (sum >> 16)
	if sum > 0xFFFF {
		sum++
	}

	return ^uint16(sum)
}

// AddDNATRule adds outbound DNAT rule for forwarding external traffic to NetBird network.
func (m *Manager) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	if m.nativeFirewall == nil {
		return nil, errNatNotSupported
	}
	return m.nativeFirewall.AddDNATRule(rule)
}

// DeleteDNATRule deletes outbound DNAT rule.
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	if m.nativeFirewall == nil {
		return errNatNotSupported
	}
	return m.nativeFirewall.DeleteDNATRule(rule)
}

// addPortRedirection adds a port redirection rule.
func (m *Manager) addPortRedirection(targetIP netip.Addr, protocol gopacket.LayerType, sourcePort, targetPort uint16) error {
	m.portDNATMutex.Lock()
	defer m.portDNATMutex.Unlock()

	rule := portDNATRule{
		protocol:   protocol,
		origPort:   sourcePort,
		targetPort: targetPort,
		targetIP:   targetIP,
	}

	m.portDNATRules = append(m.portDNATRules, rule)
	m.portDNATEnabled.Store(true)

	return nil
}

// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services.
func (m *Manager) AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	var layerType gopacket.LayerType
	switch protocol {
	case firewall.ProtocolTCP:
		layerType = layers.LayerTypeTCP
	case firewall.ProtocolUDP:
		layerType = layers.LayerTypeUDP
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return m.addPortRedirection(localAddr, layerType, sourcePort, targetPort)
}

// removePortRedirection removes a port redirection rule.
func (m *Manager) removePortRedirection(targetIP netip.Addr, protocol gopacket.LayerType, sourcePort, targetPort uint16) error {
	m.portDNATMutex.Lock()
	defer m.portDNATMutex.Unlock()

	m.portDNATRules = slices.DeleteFunc(m.portDNATRules, func(rule portDNATRule) bool {
		return rule.protocol == protocol && rule.origPort == sourcePort && rule.targetPort == targetPort && rule.targetIP.Compare(targetIP) == 0
	})

	if len(m.portDNATRules) == 0 {
		m.portDNATEnabled.Store(false)
	}

	return nil
}

// RemoveInboundDNAT removes an inbound DNAT rule.
func (m *Manager) RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error {
	var layerType gopacket.LayerType
	switch protocol {
	case firewall.ProtocolTCP:
		layerType = layers.LayerTypeTCP
	case firewall.ProtocolUDP:
		layerType = layers.LayerTypeUDP
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return m.removePortRedirection(localAddr, layerType, sourcePort, targetPort)
}

// translateInboundPortDNAT applies port-specific DNAT translation to inbound packets.
func (m *Manager) translateInboundPortDNAT(packetData []byte, d *decoder, srcIP, dstIP netip.Addr) bool {
	if !m.portDNATEnabled.Load() {
		return false
	}

	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		dstPort := uint16(d.tcp.DstPort)
		return m.applyPortRule(packetData, d, srcIP, dstIP, dstPort, layers.LayerTypeTCP, m.rewriteTCPPort)
	case layers.LayerTypeUDP:
		dstPort := uint16(d.udp.DstPort)
		return m.applyPortRule(packetData, d, netip.Addr{}, dstIP, dstPort, layers.LayerTypeUDP, m.rewriteUDPPort)
	default:
		return false
	}
}

type portRewriteFunc func(packetData []byte, d *decoder, newPort uint16, portOffset int) error

func (m *Manager) applyPortRule(packetData []byte, d *decoder, srcIP, dstIP netip.Addr, port uint16, protocol gopacket.LayerType, rewriteFn portRewriteFunc) bool {
	m.portDNATMutex.RLock()
	defer m.portDNATMutex.RUnlock()

	for _, rule := range m.portDNATRules {
		if rule.protocol != protocol || rule.targetIP.Compare(dstIP) != 0 {
			continue
		}

		if rule.targetPort == port && rule.targetIP.Compare(srcIP) == 0 {
			return false
		}

		if rule.origPort != port {
			continue
		}

		if err := rewriteFn(packetData, d, rule.targetPort, destinationPortOffset); err != nil {
			m.logger.Error1("failed to rewrite port: %v", err)
			return false
		}
		d.dnatOrigPort = rule.origPort
		return true
	}
	return false
}

// rewriteTCPPort rewrites a TCP port (source or destination) and updates checksum.
func (m *Manager) rewriteTCPPort(packetData []byte, d *decoder, newPort uint16, portOffset int) error {
	ipHeaderLen := int(d.ip4.IHL) * 4
	if ipHeaderLen < 20 || ipHeaderLen > len(packetData) {
		return errInvalidIPHeaderLength
	}

	tcpStart := ipHeaderLen
	if len(packetData) < tcpStart+4 {
		return fmt.Errorf("packet too short for TCP header")
	}

	portStart := tcpStart + portOffset
	oldPort := binary.BigEndian.Uint16(packetData[portStart : portStart+2])
	binary.BigEndian.PutUint16(packetData[portStart:portStart+2], newPort)

	if len(packetData) >= tcpStart+18 {
		checksumOffset := tcpStart + 16
		oldChecksum := binary.BigEndian.Uint16(packetData[checksumOffset : checksumOffset+2])

		var oldPortBytes, newPortBytes [2]byte
		binary.BigEndian.PutUint16(oldPortBytes[:], oldPort)
		binary.BigEndian.PutUint16(newPortBytes[:], newPort)

		newChecksum := incrementalUpdate(oldChecksum, oldPortBytes[:], newPortBytes[:])
		binary.BigEndian.PutUint16(packetData[checksumOffset:checksumOffset+2], newChecksum)
	}

	return nil
}

// rewriteUDPPort rewrites a UDP port (source or destination) and updates checksum.
func (m *Manager) rewriteUDPPort(packetData []byte, d *decoder, newPort uint16, portOffset int) error {
	ipHeaderLen := int(d.ip4.IHL) * 4
	if ipHeaderLen < 20 || ipHeaderLen > len(packetData) {
		return errInvalidIPHeaderLength
	}

	udpStart := ipHeaderLen
	if len(packetData) < udpStart+8 {
		return fmt.Errorf("packet too short for UDP header")
	}

	portStart := udpStart + portOffset
	oldPort := binary.BigEndian.Uint16(packetData[portStart : portStart+2])
	binary.BigEndian.PutUint16(packetData[portStart:portStart+2], newPort)

	checksumOffset := udpStart + 6
	if len(packetData) >= udpStart+8 {
		oldChecksum := binary.BigEndian.Uint16(packetData[checksumOffset : checksumOffset+2])
		if oldChecksum != 0 {
			var oldPortBytes, newPortBytes [2]byte
			binary.BigEndian.PutUint16(oldPortBytes[:], oldPort)
			binary.BigEndian.PutUint16(newPortBytes[:], newPort)

			newChecksum := incrementalUpdate(oldChecksum, oldPortBytes[:], newPortBytes[:])
			binary.BigEndian.PutUint16(packetData[checksumOffset:checksumOffset+2], newChecksum)
		}
	}

	return nil
}
