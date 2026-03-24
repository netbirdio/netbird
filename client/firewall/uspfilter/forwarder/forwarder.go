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
	ruleIdMap        sync.Map
	stack            *stack.Stack
	endpoint         *endpoint
	udpForwarder     *udpForwarder
	ctx              context.Context
	cancel           context.CancelFunc
	ip               tcpip.Address
	ipv6             tcpip.Address
	netstack         bool
	hasRawICMPAccess bool
	pingSemaphore    chan struct{}
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

	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, f.handleICMP)
	// TODO: gvisor's IPv6 network layer (ipv6/icmp.go) replies to ICMPv6 echo
	// requests at the network layer before our transport handler fires. Unlike
	// IPv4, it has no localAddressTemporary check or DeliverTransportPacket call
	// before replying. With promiscuous mode, this means gvisor replies to ALL
	// ICMPv6 echo (including routed traffic) with local latency.
	// Not fixed as of gvisor 20260320.
	// Fix: handle ICMPv6 echo in the USP filter before passing to the forwarder,
	// similar to how v4 ICMP worked before the forwarder existed. The forwarder
	// is needed for TCP (full proxy) and UDP (endpoint tracking), but ICMP can
	// be handled directly since it's stateless request/reply.
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, f.handleICMPv6)

	f.checkICMPCapability()

	log.Debugf("forwarder: Initialization complete with NIC %d", nicID)
	return f, nil
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
		protoNum = ipv4.ProtocolNumber
	case 6:
		if len(payload) < header.IPv6MinimumSize {
			return fmt.Errorf("IPv6 packet too small: %d bytes", len(payload))
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
	if addr.Len() == 4 {
		return netip.AddrFrom4(addr.As4())
	}
	return netip.AddrFrom16(addr.As16())
}

// checkICMPCapability tests whether we have raw ICMP socket access at startup.
func (f *Forwarder) checkICMPCapability() {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		f.hasRawICMPAccess = false
		f.logger.Debug("forwarder: No raw ICMP socket access, will use ping binary fallback")
		return
	}

	if err := conn.Close(); err != nil {
		f.logger.Debug1("forwarder: Failed to close ICMP capability test socket: %v", err)
	}

	f.hasRawICMPAccess = true
	f.logger.Debug("forwarder: Raw ICMP socket access available")
}
