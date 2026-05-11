package forwarder

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	defaultReceiveWindow = 32768
	defaultMaxInFlight   = 1024
	iosReceiveWindow     = 16384
	iosMaxInFlight       = 256
)

type Forwarder struct {
	logger     *nblog.Logger
	flowLogger nftypes.FlowLogger
	// ruleIdMap is used to store the rule ID for a given connection
	ruleIdMap          sync.Map
	stack              *stack.Stack
	endpoint           *endpoint
	udpForwarder       *udpForwarder
	ctx                context.Context
	cancel             context.CancelFunc
	ip                 tcpip.Address
	ipv6               tcpip.Address
	netstack           bool
	hasRawICMPAccess   bool
	hasRawICMPv6Access bool
	pingSemaphore      chan struct{}
}

func New(iface common.IFaceMapper, logger *nblog.Logger, flowLogger nftypes.FlowLogger, netstack bool, mtu uint16) (*Forwarder, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	nicID := tcpip.NICID(1)
	endpoint := &endpoint{
		logger: logger,
		device: iface.GetWGDevice(),
	}
	endpoint.mtu.Store(uint32(mtu))

	if err := s.CreateNIC(nicID, endpoint); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(iface.Address().IP.As4()),
			PrefixLen: iface.Address().Network.Bits(),
		},
	}

	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %s", err)
	}

	if v6 := iface.Address().IPv6; v6.IsValid() {
		v6Addr := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(v6.As16()),
				PrefixLen: iface.Address().IPv6Net.Bits(),
			},
		}
		if err := s.AddProtocolAddress(nicID, v6Addr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("add IPv6 protocol address: %s", err)
		}
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default subnet: %w", err)
	}

	defaultSubnetV6, err := tcpip.NewSubnet(
		tcpip.AddrFrom16([16]byte{}),
		tcpip.MaskFromBytes(make([]byte, 16)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default v6 subnet: %w", err)
	}

	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: defaultSubnet, NIC: nicID},
		{Destination: defaultSubnetV6, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		logger:        logger,
		flowLogger:    flowLogger,
		stack:         s,
		endpoint:      endpoint,
		udpForwarder:  newUDPForwarder(mtu, logger, flowLogger),
		ctx:           ctx,
		cancel:        cancel,
		netstack:      netstack,
		ip:            tcpip.AddrFrom4(iface.Address().IP.As4()),
		ipv6:          addrFromNetipAddr(iface.Address().IPv6),
		pingSemaphore: make(chan struct{}, 3),
	}

	receiveWindow := defaultReceiveWindow
	maxInFlight := defaultMaxInFlight
	if runtime.GOOS == "ios" {
		receiveWindow = iosReceiveWindow
		maxInFlight = iosMaxInFlight
	}

	tcpForwarder := tcp.NewForwarder(s, receiveWindow, maxInFlight, f.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, f.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	// ICMP is handled directly in InjectIncomingPacket, bypassing gVisor's
	// network layer. This avoids duplicate echo replies (v4) and the v6
	// auto-reply bug where gVisor responds at the network layer before
	// our transport handler fires.

	f.checkICMPCapability()

	log.Debugf("forwarder: Initialization complete with NIC %d", nicID)
	return f, nil
}

// SetCapture sets or clears the packet capture on the forwarder endpoint.
// This captures outbound packets that bypass the FilteredDevice (netstack forwarding).
func (f *Forwarder) SetCapture(pc PacketCapture) {
	if pc == nil {
		f.endpoint.capture.Store(nil)
		return
	}
	f.endpoint.capture.Store(&pc)
}

func (f *Forwarder) InjectIncomingPacket(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty packet")
	}

	var protoNum tcpip.NetworkProtocolNumber
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < header.IPv4MinimumSize {
			return fmt.Errorf("IPv4 packet too small: %d bytes", len(payload))
		}
		if f.handleICMPDirect(payload) {
			return nil
		}
		protoNum = ipv4.ProtocolNumber
	case 6:
		if len(payload) < header.IPv6MinimumSize {
			return fmt.Errorf("IPv6 packet too small: %d bytes", len(payload))
		}
		if f.handleICMPDirect(payload) {
			return nil
		}
		protoNum = ipv6.ProtocolNumber
	default:
		return fmt.Errorf("unknown IP version: %d", payload[0]>>4)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	if f.endpoint.dispatcher != nil {
		f.endpoint.dispatcher.DeliverNetworkPacket(protoNum, pkt)
	}
	return nil
}

// handleICMPDirect intercepts ICMP packets from raw IP payloads before they
// enter gVisor. It synthesizes the TransportEndpointID and PacketBuffer that
// the existing handlers expect, then dispatches to handleICMP/handleICMPv6.
// This bypasses gVisor's network layer which causes duplicate v4 echo replies
// and auto-replies to all v6 echo requests in promiscuous mode.
//
// Unlike gVisor's network layer, this does not validate ICMP checksums or
// reassemble IP fragments. Fragmented ICMP packets fall through to gVisor.
func parseICMPv4(payload []byte) (ipHdrLen, icmpLen int, src, dst tcpip.Address, ok bool) {
	if len(payload) < header.IPv4MinimumSize {
		return 0, 0, src, dst, false
	}
	ip := header.IPv4(payload)
	if ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		return 0, 0, src, dst, false
	}
	if ip.FragmentOffset() != 0 || ip.Flags()&header.IPv4FlagMoreFragments != 0 {
		return 0, 0, src, dst, false
	}
	ipHdrLen = int(ip.HeaderLength())
	totalLen := int(ip.TotalLength())
	if ipHdrLen < header.IPv4MinimumSize || ipHdrLen > totalLen || totalLen > len(payload) {
		return 0, 0, src, dst, false
	}
	icmpLen = totalLen - ipHdrLen
	if icmpLen < header.ICMPv4MinimumSize {
		return 0, 0, src, dst, false
	}
	return ipHdrLen, icmpLen, ip.SourceAddress(), ip.DestinationAddress(), true
}

func parseICMPv6(payload []byte) (ipHdrLen, icmpLen int, src, dst tcpip.Address, ok bool) {
	if len(payload) < header.IPv6MinimumSize {
		return 0, 0, src, dst, false
	}
	ip := header.IPv6(payload)
	declaredLen := int(ip.PayloadLength())
	hdrEnd := header.IPv6MinimumSize + declaredLen
	if hdrEnd > len(payload) {
		return 0, 0, src, dst, false
	}
	icmpStart, ok := skipIPv6ExtensionsToICMPv6(payload, ip.NextHeader(), hdrEnd)
	if !ok {
		return 0, 0, src, dst, false
	}
	icmpLen = hdrEnd - icmpStart
	if icmpLen < header.ICMPv6MinimumSize {
		return 0, 0, src, dst, false
	}
	return icmpStart, icmpLen, ip.SourceAddress(), ip.DestinationAddress(), true
}

// skipIPv6ExtensionsToICMPv6 walks the IPv6 extension-header chain starting
// after the fixed header. It advances past Hop-by-Hop, Routing, and
// Destination Options headers (which share the NextHeader+ExtLen+6+ExtLen*8
// layout) and returns the offset of the ICMPv6 payload. Fragment, ESP, AH,
// and unknown identifiers are reported as not handleable so the caller can
// defer to gVisor.
func skipIPv6ExtensionsToICMPv6(payload []byte, next uint8, hdrEnd int) (int, bool) {
	off := header.IPv6MinimumSize
	for {
		if next == uint8(header.ICMPv6ProtocolNumber) {
			return off, true
		}
		if !isWalkableIPv6ExtHdr(next) {
			return 0, false
		}
		newOff, newNext, ok := advanceIPv6ExtHdr(payload, off, hdrEnd)
		if !ok {
			return 0, false
		}
		off = newOff
		next = newNext
	}
}

func isWalkableIPv6ExtHdr(id uint8) bool {
	switch id {
	case uint8(header.IPv6HopByHopOptionsExtHdrIdentifier),
		uint8(header.IPv6RoutingExtHdrIdentifier),
		uint8(header.IPv6DestinationOptionsExtHdrIdentifier):
		return true
	}
	return false
}

func advanceIPv6ExtHdr(payload []byte, off, hdrEnd int) (int, uint8, bool) {
	if off+8 > hdrEnd {
		return 0, 0, false
	}
	extLen := (int(payload[off+1]) + 1) * 8
	if off+extLen > hdrEnd {
		return 0, 0, false
	}
	return off + extLen, payload[off], true
}

func (f *Forwarder) handleICMPDirect(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	var (
		ipHdrLen int
		icmpLen  int
		srcAddr  tcpip.Address
		dstAddr  tcpip.Address
		ok       bool
	)
	version := payload[0] >> 4
	switch version {
	case 4:
		ipHdrLen, icmpLen, srcAddr, dstAddr, ok = parseICMPv4(payload)
	case 6:
		ipHdrLen, icmpLen, srcAddr, dstAddr, ok = parseICMPv6(payload)
	}
	if !ok {
		return false
	}

	// Let gVisor handle ICMP destined for our own addresses natively.
	// Its network-layer auto-reply is correct and efficient for local traffic.
	if f.ip.Equal(dstAddr) || f.ipv6.Equal(dstAddr) {
		return false
	}

	id := stack.TransportEndpointID{
		LocalAddress:  dstAddr,
		RemoteAddress: srcAddr,
	}

	// Trim the buffer to the IP-declared length so gVisor doesn't see padding.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload[:ipHdrLen+icmpLen]),
	})
	defer pkt.DecRef()

	if _, ok := pkt.NetworkHeader().Consume(ipHdrLen); !ok {
		return false
	}
	if _, ok := pkt.TransportHeader().Consume(icmpLen); !ok {
		return false
	}

	if version == 6 {
		return f.handleICMPv6(id, pkt)
	}
	return f.handleICMP(id, pkt)
}

// Stop gracefully shuts down the forwarder
func (f *Forwarder) Stop() {
	f.cancel()

	if f.udpForwarder != nil {
		f.udpForwarder.Stop()
	}

	f.stack.Close()
	f.stack.Wait()
}

func (f *Forwarder) determineDialAddr(addr tcpip.Address) netip.Addr {
	if f.netstack && f.ip.Equal(addr) {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if f.netstack && f.ipv6.Equal(addr) {
		return netip.IPv6Loopback()
	}
	return addrToNetipAddr(addr)
}

func (f *Forwarder) RegisterRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, ruleID []byte) {
	key := buildKey(srcIP, dstIP, srcPort, dstPort)
	f.ruleIdMap.LoadOrStore(key, ruleID)
}

func (f *Forwarder) getRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) ([]byte, bool) {
	if value, ok := f.ruleIdMap.Load(buildKey(srcIP, dstIP, srcPort, dstPort)); ok {
		return value.([]byte), true
	} else if value, ok := f.ruleIdMap.Load(buildKey(dstIP, srcIP, dstPort, srcPort)); ok {
		return value.([]byte), true
	}

	return nil, false
}

func (f *Forwarder) DeleteRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) {
	if _, ok := f.ruleIdMap.LoadAndDelete(buildKey(srcIP, dstIP, srcPort, dstPort)); ok {
		return
	}
	f.ruleIdMap.LoadAndDelete(buildKey(dstIP, srcIP, dstPort, srcPort))
}

func buildKey(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) conntrack.ConnKey {
	return conntrack.ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// addrFromNetipAddr converts a netip.Addr to a gvisor tcpip.Address without allocating.
func addrFromNetipAddr(addr netip.Addr) tcpip.Address {
	if !addr.IsValid() {
		return tcpip.Address{}
	}
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

// addrToNetipAddr converts a gvisor tcpip.Address to netip.Addr without allocating.
func addrToNetipAddr(addr tcpip.Address) netip.Addr {
	switch addr.Len() {
	case 4:
		return netip.AddrFrom4(addr.As4())
	case 16:
		return netip.AddrFrom16(addr.As16())
	default:
		return netip.Addr{}
	}
}

// checkICMPCapability tests whether we have raw ICMP socket access at startup.
func (f *Forwarder) checkICMPCapability() {
	f.hasRawICMPAccess = probeRawICMP("ip4:icmp", "0.0.0.0", f.logger)
	f.hasRawICMPv6Access = probeRawICMP("ip6:ipv6-icmp", "::", f.logger)
}

func probeRawICMP(network, addr string, logger *nblog.Logger) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		logger.Debug1("forwarder: no raw %s socket access, will use ping binary fallback", network)
		return false
	}

	if err := conn.Close(); err != nil {
		logger.Debug2("forwarder: failed to close %s capability test socket: %v", network, err)
	}

	logger.Debug1("forwarder: raw %s socket access available", network)
	return true
}
