package uspfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

var ErrIPv4Only = errors.New("only IPv4 is supported for DNAT")

var (
	errInvalidIPHeaderLength = errors.New("invalid IP header length")
)

const (
	errRewriteTCPDestinationPort = "rewrite TCP destination port: %v"
)

// ipv4Checksum calculates IPv4 header checksum using optimized parallel processing for performance.
func ipv4Checksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	var sum1, sum2 uint32

	sum1 += uint32(binary.BigEndian.Uint16(header[0:2]))
	sum2 += uint32(binary.BigEndian.Uint16(header[2:4]))
	sum1 += uint32(binary.BigEndian.Uint16(header[4:6]))
	sum2 += uint32(binary.BigEndian.Uint16(header[6:8]))
	sum1 += uint32(binary.BigEndian.Uint16(header[8:10]))
	sum2 += uint32(binary.BigEndian.Uint16(header[12:14]))
	sum1 += uint32(binary.BigEndian.Uint16(header[14:16]))
	sum2 += uint32(binary.BigEndian.Uint16(header[16:18]))
	sum1 += uint32(binary.BigEndian.Uint16(header[18:20]))

	sum := sum1 + sum2

	for i := 20; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}

	sum = (sum & 0xFFFF) + (sum >> 16)
	if sum > 0xFFFF {
		sum++
	}

	return ^uint16(sum)
}

// icmpChecksum calculates ICMP checksum using parallel accumulation for high-performance processing.
func icmpChecksum(data []byte) uint16 {
	var sum1, sum2, sum3, sum4 uint32
	i := 0

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

// biDNATMap maintains bidirectional DNAT mappings for efficient forward and reverse lookups.
type biDNATMap struct {
	forward map[netip.Addr]netip.Addr
	reverse map[netip.Addr]netip.Addr
}

// portDNATRule represents a port-specific DNAT rule
type portDNATRule struct {
	protocol   gopacket.LayerType
	sourcePort uint16
	targetPort uint16
	targetIP   netip.Addr
}

// portDNATMap manages port-specific DNAT rules
type portDNATMap struct {
	rules []portDNATRule
}

// ConnKey represents a connection 4-tuple for NAT tracking.
type ConnKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
}

// portNATConn tracks port NAT state for a specific connection.
type portNATConn struct {
	rule         portDNATRule
	originalPort uint16
	translatedAt time.Time
}

// portNATTracker tracks connection-specific port NAT state
type portNATTracker struct {
	connections map[ConnKey]*portNATConn
	mutex       sync.RWMutex
}

// newPortNATTracker creates a new port NAT tracker for stateful connection tracking.
func newPortNATTracker() *portNATTracker {
	return &portNATTracker{
		connections: make(map[ConnKey]*portNATConn),
	}
}

// trackConnection tracks a connection that has port NAT applied using translated port as key.
func (t *portNATTracker) trackConnection(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, rule portDNATRule) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: rule.targetPort,
	}

	t.connections[key] = &portNATConn{
		rule:         rule,
		originalPort: dstPort,
		translatedAt: time.Now(),
	}
}

// getConnectionNAT returns NAT info for a connection if tracked, looking up by connection 4-tuple.
func (t *portNATTracker) getConnectionNAT(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) (*portNATConn, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	conn, exists := t.connections[key]
	return conn, exists
}

// shouldApplyNAT checks if NAT should be applied to a new connection to prevent bidirectional conflicts.
func (t *portNATTracker) shouldApplyNAT(srcIP, dstIP netip.Addr, dstPort uint16) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for key, conn := range t.connections {
		if key.SrcIP == dstIP && key.DstIP == srcIP &&
			conn.rule.sourcePort == dstPort && conn.originalPort == dstPort {
			return false
		}
	}
	return true
}

// cleanupConnection removes a NAT connection based on original 4-tuple for connection cleanup.
func (t *portNATTracker) cleanupConnection(srcIP, dstIP netip.Addr, srcPort uint16) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key := range t.connections {
		if key.SrcIP == srcIP && key.DstIP == dstIP && key.SrcPort == srcPort {
			delete(t.connections, key)
			return
		}
	}
}

// newBiDNATMap creates a new bidirectional DNAT mapping structure for efficient forward/reverse lookups.
func newBiDNATMap() *biDNATMap {
	return &biDNATMap{
		forward: make(map[netip.Addr]netip.Addr),
		reverse: make(map[netip.Addr]netip.Addr),
	}
}

// set adds a bidirectional DNAT mapping between original and translated addresses for both directions.
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

// getTranslated returns the translated address for a given original address from forward mapping.
func (b *biDNATMap) getTranslated(original netip.Addr) (netip.Addr, bool) {
	translated, exists := b.forward[original]
	return translated, exists
}

// getOriginal returns the original address for a given translated address from reverse mapping.
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

// getDNATTranslation returns the translated address if a mapping exists with fast-path optimization.
func (m *Manager) getDNATTranslation(addr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return addr, false
	}

	m.dnatMutex.RLock()
	translated, exists := m.dnatBiMap.getTranslated(addr)
	m.dnatMutex.RUnlock()
	return translated, exists
}

// findReverseDNATMapping finds original address for return traffic using reverse mapping.
func (m *Manager) findReverseDNATMapping(translatedAddr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return translatedAddr, false
	}

	m.dnatMutex.RLock()
	original, exists := m.dnatBiMap.getOriginal(translatedAddr)
	m.dnatMutex.RUnlock()
	return original, exists
}

// translateOutboundDNAT applies DNAT translation to outbound packets for 1:1 IP mapping.
func (m *Manager) translateOutboundDNAT(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return false
	}

	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})

	translatedIP, exists := m.getDNATTranslation(dstIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketDestination(packetData, d, translatedIP); err != nil {
		m.logger.Error("rewrite packet destination: %v", err)
		return false
	}

	m.logger.Trace("DNAT: %s -> %s", dstIP, translatedIP)
	return true
}

// translateInboundReverse applies reverse DNAT to inbound return traffic for 1:1 IP mapping.
func (m *Manager) translateInboundReverse(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})

	originalIP, exists := m.findReverseDNATMapping(srcIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketSource(packetData, d, originalIP); err != nil {
		m.logger.Error("rewrite packet source: %v", err)
		return false
	}

	m.logger.Trace("Reverse DNAT: %s -> %s", srcIP, originalIP)
	return true
}

// rewritePacketDestination replaces destination IP in the packet and updates checksums.
func (m *Manager) rewritePacketDestination(packetData []byte, d *decoder, newIP netip.Addr) error {
	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 || !newIP.Is4() {
		return ErrIPv4Only
	}

	var oldDst [4]byte
	copy(oldDst[:], packetData[16:20])
	newDst := newIP.As4()

	copy(packetData[16:20], newDst[:])

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
			m.updateTCPChecksum(packetData, ipHeaderLen, oldDst[:], newDst[:])
		case layers.LayerTypeUDP:
			m.updateUDPChecksum(packetData, ipHeaderLen, oldDst[:], newDst[:])
		case layers.LayerTypeICMPv4:
			m.updateICMPChecksum(packetData, ipHeaderLen)
		}
	}

	return nil
}

// rewritePacketSource replaces the source IP address in the packet and updates checksums.
func (m *Manager) rewritePacketSource(packetData []byte, d *decoder, newIP netip.Addr) error {
	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 || !newIP.Is4() {
		return ErrIPv4Only
	}

	var oldSrc [4]byte
	copy(oldSrc[:], packetData[12:16])
	newSrc := newIP.As4()

	copy(packetData[12:16], newSrc[:])

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
			m.updateTCPChecksum(packetData, ipHeaderLen, oldSrc[:], newSrc[:])
		case layers.LayerTypeUDP:
			m.updateUDPChecksum(packetData, ipHeaderLen, oldSrc[:], newSrc[:])
		case layers.LayerTypeICMPv4:
			m.updateICMPChecksum(packetData, ipHeaderLen)
		}
	}

	return nil
}

// updateTCPChecksum updates TCP checksum after IP address change using incremental update per RFC 1624.
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

// updateUDPChecksum updates UDP checksum after IP address change using incremental update per RFC 1624.
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

// updateICMPChecksum recalculates ICMP checksum after packet modification using full recalculation.
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

// incrementalUpdate performs incremental checksum update per RFC 1624 for performance.
func incrementalUpdate(oldChecksum uint16, oldBytes, newBytes []byte) uint16 {
	sum := uint32(^oldChecksum)

	if len(oldBytes) == 4 && len(newBytes) == 4 {
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[0:2]))
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[2:4]))
		sum += uint32(binary.BigEndian.Uint16(newBytes[0:2]))
		sum += uint32(binary.BigEndian.Uint16(newBytes[2:4]))
	} else {
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

// addPortRedirection adds port redirection rule for specified target IP, protocol and ports.
func (m *Manager) addPortRedirection(targetIP netip.Addr, protocol gopacket.LayerType, sourcePort, targetPort uint16) error {
	m.portDNATMutex.Lock()
	defer m.portDNATMutex.Unlock()

	rule := portDNATRule{
		protocol:   protocol,
		sourcePort: sourcePort,
		targetPort: targetPort,
		targetIP:   targetIP,
	}

	m.portDNATMap.rules = append(m.portDNATMap.rules, rule)
	m.portDNATEnabled.Store(true)

	return nil
}

// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services on specific ports.
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

// removePortRedirection removes port redirection rule for specified target IP, protocol and ports.
func (m *Manager) removePortRedirection(targetIP netip.Addr, protocol gopacket.LayerType, sourcePort, targetPort uint16) error {
	m.portDNATMutex.Lock()
	defer m.portDNATMutex.Unlock()

	var filteredRules []portDNATRule
	for _, rule := range m.portDNATMap.rules {
		if !(rule.protocol == protocol && rule.sourcePort == sourcePort && rule.targetPort == targetPort && rule.targetIP.Compare(targetIP) == 0) {
			filteredRules = append(filteredRules, rule)
		}
	}
	m.portDNATMap.rules = filteredRules

	if len(m.portDNATMap.rules) == 0 {
		m.portDNATEnabled.Store(false)
	}

	return nil
}

// RemoveInboundDNAT removes inbound DNAT rule for specified local address and ports.
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

// translateInboundPortDNAT applies stateful port-specific DNAT translation to inbound packets.
func (m *Manager) translateInboundPortDNAT(packetData []byte, d *decoder) bool {
	if !m.portDNATEnabled.Load() {
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return false
	}

	if len(d.decoded) < 2 || d.decoded[1] != layers.LayerTypeTCP {
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})
	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})
	srcPort := uint16(d.tcp.SrcPort)
	dstPort := uint16(d.tcp.DstPort)

	if m.handleReturnTraffic(packetData, d, srcIP, dstIP, srcPort, dstPort) {
		return true
	}

	return m.handleNewConnection(packetData, d, srcIP, dstIP, srcPort, dstPort)
}

// handleReturnTraffic processes return traffic for existing NAT connections.
func (m *Manager) handleReturnTraffic(packetData []byte, d *decoder, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) bool {
	if m.isTranslatedPortTraffic(srcIP, srcPort) {
		return false
	}

	if handled := m.handleExistingNATConnection(packetData, d, srcIP, dstIP, srcPort, dstPort); handled {
		return true
	}

	return m.handleForwardTrafficInExistingConnections(packetData, d, srcIP, dstIP, srcPort, dstPort)
}

// isTranslatedPortTraffic checks if traffic is from a translated port that should be handled by outbound reverse.
func (m *Manager) isTranslatedPortTraffic(srcIP netip.Addr, srcPort uint16) bool {
	m.portDNATMutex.RLock()
	defer m.portDNATMutex.RUnlock()

	for _, rule := range m.portDNATMap.rules {
		if rule.protocol == layers.LayerTypeTCP && rule.targetPort == srcPort &&
			rule.targetIP.Unmap().Compare(srcIP.Unmap()) == 0 {
			return true
		}
	}
	return false
}

// handleExistingNATConnection processes return traffic for existing NAT connections.
func (m *Manager) handleExistingNATConnection(packetData []byte, d *decoder, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) bool {
	if natConn, exists := m.portNATTracker.getConnectionNAT(dstIP, srcIP, dstPort, srcPort); exists {
		if err := m.rewriteTCPDestinationPort(packetData, d, natConn.originalPort); err != nil {
			m.logger.Error(errRewriteTCPDestinationPort, err)
			return false
		}
		m.logger.Trace("Inbound Port DNAT (return): %s:%d -> %s:%d", dstIP, srcPort, dstIP, natConn.originalPort)
		return true
	}
	return false
}

// handleForwardTrafficInExistingConnections processes forward traffic in existing connections.
func (m *Manager) handleForwardTrafficInExistingConnections(packetData []byte, d *decoder, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) bool {
	m.portDNATMutex.RLock()
	defer m.portDNATMutex.RUnlock()

	for _, rule := range m.portDNATMap.rules {
		if rule.protocol != layers.LayerTypeTCP || rule.sourcePort != dstPort {
			continue
		}
		if rule.targetIP.Unmap().Compare(dstIP.Unmap()) != 0 {
			continue
		}

		if _, exists := m.portNATTracker.getConnectionNAT(srcIP, dstIP, srcPort, rule.targetPort); !exists {
			continue
		}

		if err := m.rewriteTCPDestinationPort(packetData, d, rule.targetPort); err != nil {
			m.logger.Error(errRewriteTCPDestinationPort, err)
			return false
		}
		return true
	}

	return false
}

// handleNewConnection processes new connections that match port DNAT rules.
func (m *Manager) handleNewConnection(packetData []byte, d *decoder, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) bool {
	m.portDNATMutex.RLock()
	defer m.portDNATMutex.RUnlock()

	for _, rule := range m.portDNATMap.rules {
		if m.applyPortDNATRule(packetData, d, rule, srcIP, dstIP, srcPort, dstPort) {
			return true
		}
	}
	return false
}

// applyPortDNATRule applies a specific port DNAT rule if conditions are met.
func (m *Manager) applyPortDNATRule(packetData []byte, d *decoder, rule portDNATRule, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) bool {
	if rule.protocol != layers.LayerTypeTCP || rule.sourcePort != dstPort {
		return false
	}

	if rule.targetIP.Unmap().Compare(dstIP.Unmap()) != 0 {
		return false
	}

	if !m.portNATTracker.shouldApplyNAT(srcIP, dstIP, dstPort) {
		return false
	}

	if err := m.rewriteTCPDestinationPort(packetData, d, rule.targetPort); err != nil {
		m.logger.Error(errRewriteTCPDestinationPort, err)
		return false
	}

	m.portNATTracker.trackConnection(srcIP, dstIP, srcPort, dstPort, rule)
	m.logger.Trace("Inbound Port DNAT (new): %s:%d -> %s:%d (tracked: %s:%d -> %s:%d)", dstIP, rule.sourcePort, dstIP, rule.targetPort, srcIP, srcPort, dstIP, rule.targetPort)
	return true
}

// rewriteTCPDestinationPort rewrites the destination port in a TCP packet and updates checksum.
func (m *Manager) rewriteTCPDestinationPort(packetData []byte, d *decoder, newPort uint16) error {
	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return ErrIPv4Only
	}

	if len(d.decoded) < 2 || d.decoded[1] != layers.LayerTypeTCP {
		return fmt.Errorf("not a TCP packet")
	}

	ipHeaderLen := int(d.ip4.IHL) * 4
	if ipHeaderLen < 20 || ipHeaderLen > len(packetData) {
		return errInvalidIPHeaderLength
	}

	tcpStart := ipHeaderLen
	if len(packetData) < tcpStart+4 {
		return fmt.Errorf("packet too short for TCP header")
	}

	oldPort := binary.BigEndian.Uint16(packetData[tcpStart+2 : tcpStart+4])

	binary.BigEndian.PutUint16(packetData[tcpStart+2:tcpStart+4], newPort)

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

// rewriteTCPSourcePort rewrites the source port in a TCP packet and updates checksum.
func (m *Manager) rewriteTCPSourcePort(packetData []byte, d *decoder, newPort uint16) error {
	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return ErrIPv4Only
	}

	if len(d.decoded) < 2 || d.decoded[1] != layers.LayerTypeTCP {
		return fmt.Errorf("not a TCP packet")
	}

	ipHeaderLen := int(d.ip4.IHL) * 4
	if ipHeaderLen < 20 || ipHeaderLen > len(packetData) {
		return errInvalidIPHeaderLength
	}

	tcpStart := ipHeaderLen
	if len(packetData) < tcpStart+4 {
		return fmt.Errorf("packet too short for TCP header")
	}

	oldPort := binary.BigEndian.Uint16(packetData[tcpStart : tcpStart+2])

	binary.BigEndian.PutUint16(packetData[tcpStart:tcpStart+2], newPort)

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

// translateOutboundPortReverse applies stateful reverse port DNAT to outbound return traffic for SSH redirection.
func (m *Manager) translateOutboundPortReverse(packetData []byte, d *decoder) bool {
	if !m.portDNATEnabled.Load() {
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		return false
	}

	if len(d.decoded) < 2 || d.decoded[1] != layers.LayerTypeTCP {
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})
	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})
	srcPort := uint16(d.tcp.SrcPort)
	dstPort := uint16(d.tcp.DstPort)

	// For outbound reverse, we need to find the connection using the same key as when it was stored
	// Connection was stored as: srcIP, dstIP, srcPort, translatedPort
	// So for return traffic (srcIP=server, dstIP=client), we need: dstIP, srcIP, dstPort, srcPort
	if natConn, exists := m.portNATTracker.getConnectionNAT(dstIP, srcIP, dstPort, srcPort); exists {
		if err := m.rewriteTCPSourcePort(packetData, d, natConn.rule.sourcePort); err != nil {
			m.logger.Error("rewrite TCP source port: %v", err)
			return false
		}

		return true
	}

	return false
}
