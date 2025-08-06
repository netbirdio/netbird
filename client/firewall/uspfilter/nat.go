package uspfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket/layers"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

var ErrIPv4Only = errors.New("only IPv4 is supported for DNAT")

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

type biDNATMap struct {
	forward map[netip.Addr]netip.Addr
	reverse map[netip.Addr]netip.Addr
}

func newBiDNATMap() *biDNATMap {
	return &biDNATMap{
		forward: make(map[netip.Addr]netip.Addr),
		reverse: make(map[netip.Addr]netip.Addr),
	}
}

func (b *biDNATMap) set(original, translated netip.Addr) {
	b.forward[original] = translated
	b.reverse[translated] = original
}

func (b *biDNATMap) delete(original netip.Addr) {
	if translated, exists := b.forward[original]; exists {
		delete(b.forward, original)
		delete(b.reverse, translated)
	}
}

func (b *biDNATMap) getTranslated(original netip.Addr) (netip.Addr, bool) {
	translated, exists := b.forward[original]
	return translated, exists
}

func (b *biDNATMap) getOriginal(translated netip.Addr) (netip.Addr, bool) {
	original, exists := b.reverse[translated]
	return original, exists
}

func (m *Manager) AddInternalDNATMapping(originalAddr, translatedAddr netip.Addr) error {
	if !originalAddr.IsValid() || !translatedAddr.IsValid() {
		return fmt.Errorf("invalid IP addresses")
	}

	if m.localipmanager.IsLocalIP(translatedAddr) {
		return fmt.Errorf("cannot map to local IP: %s", translatedAddr)
	}

	m.dnatMutex.Lock()
	defer m.dnatMutex.Unlock()

	// Initialize both maps together if either is nil
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

// RemoveInternalDNATMapping removes a 1:1 IP address mapping
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

// getDNATTranslation returns the translated address if a mapping exists
func (m *Manager) getDNATTranslation(addr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return addr, false
	}

	m.dnatMutex.RLock()
	translated, exists := m.dnatBiMap.getTranslated(addr)
	m.dnatMutex.RUnlock()
	return translated, exists
}

// findReverseDNATMapping finds original address for return traffic
func (m *Manager) findReverseDNATMapping(translatedAddr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return translatedAddr, false
	}

	m.dnatMutex.RLock()
	original, exists := m.dnatBiMap.getOriginal(translatedAddr)
	m.dnatMutex.RUnlock()
	return original, exists
}

// translateOutboundDNAT applies DNAT translation to outbound packets
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
		m.logger.Error1("Failed to rewrite packet destination: %v", err)
		return false
	}

	m.logger.Trace2("DNAT: %s -> %s", dstIP, translatedIP)
	return true
}

// translateInboundReverse applies reverse DNAT to inbound return traffic
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
		m.logger.Error1("Failed to rewrite packet source: %v", err)
		return false
	}

	m.logger.Trace2("Reverse DNAT: %s -> %s", srcIP, originalIP)
	return true
}

// rewritePacketDestination replaces destination IP in the packet
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
		return fmt.Errorf("invalid IP header length")
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

// rewritePacketSource replaces the source IP address in the packet
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
		return fmt.Errorf("invalid IP header length")
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

// incrementalUpdate performs incremental checksum update per RFC 1624
func incrementalUpdate(oldChecksum uint16, oldBytes, newBytes []byte) uint16 {
	sum := uint32(^oldChecksum)

	// Fast path for IPv4 addresses (4 bytes) - most common case
	if len(oldBytes) == 4 && len(newBytes) == 4 {
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[0:2]))
		sum += uint32(^binary.BigEndian.Uint16(oldBytes[2:4]))
		sum += uint32(binary.BigEndian.Uint16(newBytes[0:2]))
		sum += uint32(binary.BigEndian.Uint16(newBytes[2:4]))
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

// AddDNATRule adds a DNAT rule (delegates to native firewall for port forwarding)
func (m *Manager) AddDNATRule(rule firewall.ForwardRule) (firewall.Rule, error) {
	if m.nativeFirewall == nil {
		return nil, errNatNotSupported
	}
	return m.nativeFirewall.AddDNATRule(rule)
}

// DeleteDNATRule deletes a DNAT rule (delegates to native firewall)
func (m *Manager) DeleteDNATRule(rule firewall.Rule) error {
	if m.nativeFirewall == nil {
		return errNatNotSupported
	}
	return m.nativeFirewall.DeleteDNATRule(rule)
}
