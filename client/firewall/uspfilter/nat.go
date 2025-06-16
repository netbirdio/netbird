package uspfilter

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/gopacket/layers"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

func ipv4Checksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

func (m *Manager) AddInternalDNATMapping(originalAddr, translatedAddr netip.Addr) error {
	if !originalAddr.IsValid() || !translatedAddr.IsValid() {
		return fmt.Errorf("invalid IP addresses")
	}

	if m.localipmanager.IsLocalIP(translatedAddr) {
		return fmt.Errorf("cannot map to local IP: %s", translatedAddr)
	}

	m.dnatMutex.Lock()
	m.dnatMappings[originalAddr] = translatedAddr
	if len(m.dnatMappings) == 1 {
		m.dnatEnabled.Store(true)
	}
	m.dnatMutex.Unlock()

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
	translated, exists := m.dnatMappings[addr]
	m.dnatMutex.RUnlock()
	return translated, exists
}

// findReverseDNATMapping finds original address for return traffic
func (m *Manager) findReverseDNATMapping(translatedAddr netip.Addr) (netip.Addr, bool) {
	if !m.dnatEnabled.Load() {
		return translatedAddr, false
	}

	m.dnatMutex.RLock()
	defer m.dnatMutex.RUnlock()

	for original, translated := range m.dnatMappings {
		if translated == translatedAddr {
			return original, true
		}
	}

	return translatedAddr, false
}

// translateOutboundDNAT applies DNAT translation to outbound packets
func (m *Manager) translateOutboundDNAT(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	_, dstIP := m.extractIPs(d)
	if !dstIP.IsValid() || !dstIP.Is4() {
		return false
	}

	translatedIP, exists := m.getDNATTranslation(dstIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketDestination(packetData, d, translatedIP); err != nil {
		m.logger.Error("Failed to rewrite packet destination: %v", err)
		return false
	}

	m.logger.Trace("DNAT: %s -> %s", dstIP, translatedIP)
	return true
}

// translateInboundReverse applies reverse DNAT to inbound return traffic
func (m *Manager) translateInboundReverse(packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		return false
	}

	srcIP, _ := m.extractIPs(d)
	if !srcIP.IsValid() || !srcIP.Is4() {
		return false
	}

	originalIP, exists := m.findReverseDNATMapping(srcIP)
	if !exists {
		return false
	}

	if err := m.rewritePacketSource(packetData, d, originalIP); err != nil {
		m.logger.Error("Failed to rewrite packet source: %v", err)
		return false
	}

	m.logger.Trace("Reverse DNAT: %s -> %s", srcIP, originalIP)
	return true
}

// rewritePacketDestination replaces destination IP in the packet
func (m *Manager) rewritePacketDestination(packetData []byte, d *decoder, newIP netip.Addr) error {
	if d.decoded[0] != layers.LayerTypeIPv4 || !newIP.Is4() {
		return fmt.Errorf("only IPv4 supported")
	}

	oldDst := make([]byte, 4)
	copy(oldDst, packetData[16:20])
	newDst := newIP.AsSlice()

	copy(packetData[16:20], newDst)

	ipHeaderLen := int(d.ip4.IHL) * 4
	binary.BigEndian.PutUint16(packetData[10:12], 0)
	ipChecksum := ipv4Checksum(packetData[:ipHeaderLen])
	binary.BigEndian.PutUint16(packetData[10:12], ipChecksum)

	if len(d.decoded) > 1 {
		switch d.decoded[1] {
		case layers.LayerTypeTCP:
			m.updateTCPChecksum(packetData, ipHeaderLen, oldDst, newDst)
		case layers.LayerTypeUDP:
			m.updateUDPChecksum(packetData, ipHeaderLen, oldDst, newDst)
		case layers.LayerTypeICMPv4:
			m.updateICMPChecksum(packetData, ipHeaderLen)
		}
	}

	return nil
}

// rewritePacketSource replaces the source IP address in the packet
func (m *Manager) rewritePacketSource(packetData []byte, d *decoder, newIP netip.Addr) error {
	if d.decoded[0] != layers.LayerTypeIPv4 || !newIP.Is4() {
		return fmt.Errorf("only IPv4 supported")
	}

	oldSrc := make([]byte, 4)
	copy(oldSrc, packetData[12:16])
	newSrc := newIP.AsSlice()

	copy(packetData[12:16], newSrc)

	ipHeaderLen := int(d.ip4.IHL) * 4
	binary.BigEndian.PutUint16(packetData[10:12], 0)
	ipChecksum := ipv4Checksum(packetData[:ipHeaderLen])
	binary.BigEndian.PutUint16(packetData[10:12], ipChecksum)

	if len(d.decoded) > 1 {
		switch d.decoded[1] {
		case layers.LayerTypeTCP:
			m.updateTCPChecksum(packetData, ipHeaderLen, oldSrc, newSrc)
		case layers.LayerTypeUDP:
			m.updateUDPChecksum(packetData, ipHeaderLen, oldSrc, newSrc)
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

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
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
