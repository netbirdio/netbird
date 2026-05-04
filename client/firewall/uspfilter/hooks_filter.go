package uspfilter

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/device"
)

const (
	ipv4HeaderMinLen = 20
	ipv4ProtoOffset  = 9
	ipv4FlagsOffset  = 6
	ipv4DstOffset    = 16
	ipProtoUDP       = 17
	ipProtoTCP       = 6
	ipv4FragOffMask  = 0x1fff
	// dstPortOffset is the offset of the destination port within a UDP or TCP header.
	dstPortOffset = 2
)

// HooksFilter is a minimal packet filter that only handles outbound DNS hooks.
// It is installed on the WireGuard interface when the userspace bind is active
// but a full firewall filter (Manager) is not needed because a native kernel
// firewall (nftables/iptables) handles packet filtering.
type HooksFilter struct {
	udpHook atomic.Pointer[common.PacketHook]
	tcpHook atomic.Pointer[common.PacketHook]
}

var _ device.PacketFilter = (*HooksFilter)(nil)

// FilterOutbound checks outbound packets for DNS hook matches.
// Only IPv4 packets matching the registered hook IP:port are intercepted.
// IPv6 and non-IP packets pass through unconditionally.
func (f *HooksFilter) FilterOutbound(packetData []byte, _ int) bool {
	if len(packetData) < ipv4HeaderMinLen {
		return false
	}

	// Only process IPv4 packets, let everything else pass through.
	if packetData[0]>>4 != 4 {
		return false
	}

	ihl := int(packetData[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(packetData) < ihl+4 {
		return false
	}

	// Skip non-first fragments: they don't carry L4 headers.
	flagsAndOffset := binary.BigEndian.Uint16(packetData[ipv4FlagsOffset : ipv4FlagsOffset+2])
	if flagsAndOffset&ipv4FragOffMask != 0 {
		return false
	}

	dstIP, ok := netip.AddrFromSlice(packetData[ipv4DstOffset : ipv4DstOffset+4])
	if !ok {
		return false
	}

	proto := packetData[ipv4ProtoOffset]
	dstPort := binary.BigEndian.Uint16(packetData[ihl+dstPortOffset : ihl+dstPortOffset+2])

	switch proto {
	case ipProtoUDP:
		return common.HookMatches(f.udpHook.Load(), dstIP, dstPort, packetData)
	case ipProtoTCP:
		return common.HookMatches(f.tcpHook.Load(), dstIP, dstPort, packetData)
	default:
		return false
	}
}

// FilterInbound allows all inbound packets (native firewall handles filtering).
func (f *HooksFilter) FilterInbound([]byte, int) bool {
	return false
}

// SetUDPPacketHook registers the UDP packet hook.
func (f *HooksFilter) SetUDPPacketHook(ip netip.Addr, dPort uint16, hook func([]byte) bool) {
	common.SetHook(&f.udpHook, ip, dPort, hook)
}

// SetTCPPacketHook registers the TCP packet hook.
func (f *HooksFilter) SetTCPPacketHook(ip netip.Addr, dPort uint16, hook func([]byte) bool) {
	common.SetHook(&f.tcpHook, ip, dPort, hook)
}
