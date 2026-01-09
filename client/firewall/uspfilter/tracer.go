package uspfilter

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

type PacketStage int

const (
	StageReceived PacketStage = iota
	StageInboundPortDNAT
	StageInbound1to1NAT
	StageConntrack
	StagePeerACL
	StageRouting
	StageRouteACL
	StageForwarding
	StageCompleted
	StageOutbound1to1NAT
	StageOutboundPortReverse
)

const msgProcessingCompleted = "Processing completed"

func (s PacketStage) String() string {
	return map[PacketStage]string{
		StageReceived:            "Received",
		StageInboundPortDNAT:     "Inbound Port DNAT",
		StageInbound1to1NAT:      "Inbound 1:1 NAT",
		StageConntrack:           "Connection Tracking",
		StagePeerACL:             "Peer ACL",
		StageRouting:             "Routing",
		StageRouteACL:            "Route ACL",
		StageForwarding:          "Forwarding",
		StageCompleted:           "Completed",
		StageOutbound1to1NAT:     "Outbound 1:1 NAT",
		StageOutboundPortReverse: "Outbound DNAT Reverse",
	}[s]
}

type ForwarderAction struct {
	Action     string
	RemoteAddr string
	Error      error
}

type TraceResult struct {
	Timestamp       time.Time
	Stage           PacketStage
	Message         string
	Allowed         bool
	ForwarderAction *ForwarderAction
}

type PacketTrace struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	Protocol        string
	SourcePort      uint16
	DestinationPort uint16
	Direction       fw.RuleDirection
	Results         []TraceResult
}

type TCPState struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

type PacketBuilder struct {
	SrcIP       netip.Addr
	DstIP       netip.Addr
	Protocol    fw.Protocol
	SrcPort     uint16
	DstPort     uint16
	ICMPType    uint8
	ICMPCode    uint8
	Direction   fw.RuleDirection
	PayloadSize int
	TCPState    *TCPState
}

func (t *PacketTrace) AddResult(stage PacketStage, message string, allowed bool) {
	t.Results = append(t.Results, TraceResult{
		Timestamp: time.Now(),
		Stage:     stage,
		Message:   message,
		Allowed:   allowed,
	})
}

func (t *PacketTrace) AddResultWithForwarder(stage PacketStage, message string, allowed bool, action *ForwarderAction) {
	t.Results = append(t.Results, TraceResult{
		Timestamp:       time.Now(),
		Stage:           stage,
		Message:         message,
		Allowed:         allowed,
		ForwarderAction: action,
	})
}

func (p *PacketBuilder) Build() ([]byte, error) {
	ip := p.buildIPLayer()
	pktLayers := []gopacket.SerializableLayer{ip}

	transportLayer, err := p.buildTransportLayer(ip)
	if err != nil {
		return nil, err
	}
	pktLayers = append(pktLayers, transportLayer...)

	if p.PayloadSize > 0 {
		payload := make([]byte, p.PayloadSize)
		pktLayers = append(pktLayers, gopacket.Payload(payload))
	}

	return serializePacket(pktLayers)
}

func (p *PacketBuilder) buildIPLayer() *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocol(getIPProtocolNumber(p.Protocol)),
		SrcIP:    p.SrcIP.AsSlice(),
		DstIP:    p.DstIP.AsSlice(),
	}
}

func (p *PacketBuilder) buildTransportLayer(ip *layers.IPv4) ([]gopacket.SerializableLayer, error) {
	switch p.Protocol {
	case "tcp":
		return p.buildTCPLayer(ip)
	case "udp":
		return p.buildUDPLayer(ip)
	case "icmp":
		return p.buildICMPLayer()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
}

func (p *PacketBuilder) buildTCPLayer(ip *layers.IPv4) ([]gopacket.SerializableLayer, error) {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(p.SrcPort),
		DstPort: layers.TCPPort(p.DstPort),
		Window:  65535,
		SYN:     p.TCPState != nil && p.TCPState.SYN,
		ACK:     p.TCPState != nil && p.TCPState.ACK,
		FIN:     p.TCPState != nil && p.TCPState.FIN,
		RST:     p.TCPState != nil && p.TCPState.RST,
		PSH:     p.TCPState != nil && p.TCPState.PSH,
		URG:     p.TCPState != nil && p.TCPState.URG,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set network layer for TCP checksum: %w", err)
	}
	return []gopacket.SerializableLayer{tcp}, nil
}

func (p *PacketBuilder) buildUDPLayer(ip *layers.IPv4) ([]gopacket.SerializableLayer, error) {
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(p.SrcPort),
		DstPort: layers.UDPPort(p.DstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set network layer for UDP checksum: %w", err)
	}
	return []gopacket.SerializableLayer{udp}, nil
}

func (p *PacketBuilder) buildICMPLayer() ([]gopacket.SerializableLayer, error) {
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(p.ICMPType, p.ICMPCode),
	}
	if p.ICMPType == layers.ICMPv4TypeEchoRequest || p.ICMPType == layers.ICMPv4TypeEchoReply {
		icmp.Id = uint16(1)
		icmp.Seq = uint16(1)
	}
	return []gopacket.SerializableLayer{icmp}, nil
}

func serializePacket(layers []gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		return nil, fmt.Errorf("serialize packet: %w", err)
	}
	return buf.Bytes(), nil
}

func getIPProtocolNumber(protocol fw.Protocol) int {
	switch protocol {
	case fw.ProtocolTCP:
		return int(layers.IPProtocolTCP)
	case fw.ProtocolUDP:
		return int(layers.IPProtocolUDP)
	case fw.ProtocolICMP:
		return int(layers.IPProtocolICMPv4)
	default:
		return 0
	}
}

func (m *Manager) TracePacketFromBuilder(builder *PacketBuilder) (*PacketTrace, error) {
	packetData, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build packet: %w", err)
	}

	return m.TracePacket(packetData, builder.Direction), nil
}

func (m *Manager) TracePacket(packetData []byte, direction fw.RuleDirection) *PacketTrace {

	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	trace := &PacketTrace{Direction: direction}

	// Initial packet decoding
	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		trace.AddResult(StageReceived, fmt.Sprintf("Failed to decode packet: %v", err), false)
		return trace
	}

	// Extract base packet info
	srcIP, dstIP := m.extractIPs(d)
	trace.SourceIP = srcIP
	trace.DestinationIP = dstIP

	// Determine protocol and ports
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		trace.Protocol = "TCP"
		trace.SourcePort = uint16(d.tcp.SrcPort)
		trace.DestinationPort = uint16(d.tcp.DstPort)
	case layers.LayerTypeUDP:
		trace.Protocol = "UDP"
		trace.SourcePort = uint16(d.udp.SrcPort)
		trace.DestinationPort = uint16(d.udp.DstPort)
	case layers.LayerTypeICMPv4:
		trace.Protocol = "ICMP"
	}

	trace.AddResult(StageReceived, fmt.Sprintf("Received %s packet: %s:%d -> %s:%d",
		trace.Protocol, srcIP, trace.SourcePort, dstIP, trace.DestinationPort), true)

	if direction == fw.RuleDirectionOUT {
		return m.traceOutbound(packetData, trace)
	}

	return m.traceInbound(packetData, trace, d, srcIP, dstIP)
}

func (m *Manager) traceInbound(packetData []byte, trace *PacketTrace, d *decoder, srcIP netip.Addr, dstIP netip.Addr) *PacketTrace {
	if m.handleInboundDNAT(trace, packetData, d, &srcIP, &dstIP) {
		return trace
	}

	if m.stateful && m.handleConntrackState(trace, d, srcIP, dstIP) {
		return trace
	}

	if m.localipmanager.IsLocalIP(dstIP) {
		if m.handleLocalDelivery(trace, packetData, d, srcIP, dstIP) {
			return trace
		}
	}

	if !m.handleRouting(trace) {
		return trace
	}

	if m.nativeRouter.Load() {
		return m.handleNativeRouter(trace)
	}

	return m.handleRouteACLs(trace, d, srcIP, dstIP)
}

func (m *Manager) handleConntrackState(trace *PacketTrace, d *decoder, srcIP, dstIP netip.Addr) bool {
	allowed := m.isValidTrackedConnection(d, srcIP, dstIP, 0)
	msg := "No existing connection found"
	if allowed {
		msg = m.buildConntrackStateMessage(d)
		trace.AddResult(StageConntrack, msg, true)
		trace.AddResult(StageCompleted, "Packet allowed by connection tracking", true)
		return true
	}
	trace.AddResult(StageConntrack, msg, false)
	return false
}

func (m *Manager) buildConntrackStateMessage(d *decoder) string {
	msg := "Matched existing connection state"
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		flags := getTCPFlags(&d.tcp)
		msg += fmt.Sprintf(" (TCP Flags: SYN=%v ACK=%v RST=%v FIN=%v)",
			flags&conntrack.TCPSyn != 0,
			flags&conntrack.TCPAck != 0,
			flags&conntrack.TCPRst != 0,
			flags&conntrack.TCPFin != 0)
	case layers.LayerTypeICMPv4:
		msg += fmt.Sprintf(" (ICMP ID=%d, Seq=%d)", d.icmp4.Id, d.icmp4.Seq)
	}
	return msg
}

func (m *Manager) handleLocalDelivery(trace *PacketTrace, packetData []byte, d *decoder, srcIP, dstIP netip.Addr) bool {
	trace.AddResult(StageRouting, "Packet destined for local delivery", true)

	ruleId, blocked := m.peerACLsBlock(srcIP, d, packetData)

	strRuleId := "<no id>"
	if ruleId != nil {
		strRuleId = string(ruleId)
	}
	msg := fmt.Sprintf("Allowed by peer ACL rules (%s)", strRuleId)
	if blocked {
		msg = fmt.Sprintf("Blocked by peer ACL rules (%s)", strRuleId)
		trace.AddResult(StagePeerACL, msg, false)
		trace.AddResult(StageCompleted, "Packet dropped - ACL denied", false)
		return true
	}

	trace.AddResult(StagePeerACL, msg, true)

	// Handle netstack mode
	if m.netstack {
		switch {
		case !m.localForwarding:
			trace.AddResult(StageCompleted, "Packet sent to virtual stack", true)
		case m.forwarder.Load() != nil:
			m.addForwardingResult(trace, "proxy-local", "127.0.0.1", true)
			trace.AddResult(StageCompleted, msgProcessingCompleted, true)
		default:
			trace.AddResult(StageCompleted, "Packet dropped - forwarder not initialized", false)
		}
		return true
	}

	// In normal mode, packets are allowed through for local delivery
	trace.AddResult(StageCompleted, msgProcessingCompleted, true)
	return true
}

func (m *Manager) handleRouting(trace *PacketTrace) bool {
	if !m.routingEnabled.Load() {
		trace.AddResult(StageRouting, "Routing disabled", false)
		trace.AddResult(StageCompleted, "Packet dropped - routing disabled", false)
		return false
	}
	trace.AddResult(StageRouting, "Routing enabled, checking ACLs", true)
	return true
}

func (m *Manager) handleNativeRouter(trace *PacketTrace) *PacketTrace {
	trace.AddResult(StageRouteACL, "Using native router, skipping ACL checks", true)
	trace.AddResult(StageForwarding, "Forwarding via native router", true)
	trace.AddResult(StageCompleted, msgProcessingCompleted, true)
	return trace
}

func (m *Manager) handleRouteACLs(trace *PacketTrace, d *decoder, srcIP, dstIP netip.Addr) *PacketTrace {
	protoLayer := d.decoded[1]
	srcPort, dstPort := getPortsFromPacket(d)
	id, allowed := m.routeACLsPass(srcIP, dstIP, protoLayer, srcPort, dstPort)

	strId := string(id)
	if id == nil {
		strId = "<no id>"
	}

	msg := fmt.Sprintf("Allowed by route ACLs (%s)", strId)
	if !allowed {
		msg = fmt.Sprintf("Blocked by route ACLs (%s)", strId)
	}
	trace.AddResult(StageRouteACL, msg, allowed)

	if allowed && m.forwarder.Load() != nil {
		m.addForwardingResult(trace, "proxy-remote", fmt.Sprintf("%s:%d", dstIP, dstPort), true)
	}

	trace.AddResult(StageCompleted, msgProcessingCompleted, allowed)
	return trace
}

func (m *Manager) addForwardingResult(trace *PacketTrace, action, remoteAddr string, allowed bool) {
	fwdAction := &ForwarderAction{
		Action:     action,
		RemoteAddr: remoteAddr,
	}
	trace.AddResultWithForwarder(StageForwarding,
		fmt.Sprintf("Forwarding to %s", fwdAction.Action), allowed, fwdAction)
}

func (m *Manager) traceOutbound(packetData []byte, trace *PacketTrace) *PacketTrace {
	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)

	if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
		trace.AddResult(StageCompleted, "Packet dropped - decode error", false)
		return trace
	}

	m.handleOutboundDNAT(trace, packetData, d)

	dropped := m.filterOutbound(packetData, 0)
	if dropped {
		trace.AddResult(StageCompleted, "Packet dropped by outgoing hook", false)
	} else {
		trace.AddResult(StageCompleted, "Packet allowed (outgoing)", true)
	}
	return trace
}

func (m *Manager) handleInboundDNAT(trace *PacketTrace, packetData []byte, d *decoder, srcIP, dstIP *netip.Addr) bool {
	portDNATApplied := m.traceInboundPortDNAT(trace, packetData, d)
	if portDNATApplied {
		if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
			trace.AddResult(StageInboundPortDNAT, "Failed to re-decode after port DNAT", false)
			return true
		}
		*srcIP, *dstIP = m.extractIPs(d)
		trace.DestinationPort = m.getDestPort(d)
	}

	nat1to1Applied := m.traceInbound1to1NAT(trace, packetData, d)
	if nat1to1Applied {
		if err := d.parser.DecodeLayers(packetData, &d.decoded); err != nil {
			trace.AddResult(StageInbound1to1NAT, "Failed to re-decode after 1:1 NAT", false)
			return true
		}
		*srcIP, *dstIP = m.extractIPs(d)
	}

	return false
}

func (m *Manager) traceInboundPortDNAT(trace *PacketTrace, packetData []byte, d *decoder) bool {
	if !m.portDNATEnabled.Load() {
		trace.AddResult(StageInboundPortDNAT, "Port DNAT not enabled", true)
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		trace.AddResult(StageInboundPortDNAT, "Not IPv4, skipping port DNAT", true)
		return false
	}

	if len(d.decoded) < 2 {
		trace.AddResult(StageInboundPortDNAT, "No transport layer, skipping port DNAT", true)
		return false
	}

	protocol := d.decoded[1]
	if protocol != layers.LayerTypeTCP && protocol != layers.LayerTypeUDP {
		trace.AddResult(StageInboundPortDNAT, "Not TCP/UDP, skipping port DNAT", true)
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})
	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})
	var originalPort uint16
	if protocol == layers.LayerTypeTCP {
		originalPort = uint16(d.tcp.DstPort)
	} else {
		originalPort = uint16(d.udp.DstPort)
	}

	translated := m.translateInboundPortDNAT(packetData, d, srcIP, dstIP)
	if translated {
		ipHeaderLen := int((packetData[0] & 0x0F) * 4)
		translatedPort := uint16(packetData[ipHeaderLen+2])<<8 | uint16(packetData[ipHeaderLen+3])

		protoStr := "TCP"
		if protocol == layers.LayerTypeUDP {
			protoStr = "UDP"
		}
		msg := fmt.Sprintf("%s port DNAT applied: %s:%d -> %s:%d", protoStr, dstIP, originalPort, dstIP, translatedPort)
		trace.AddResult(StageInboundPortDNAT, msg, true)
		return true
	}

	trace.AddResult(StageInboundPortDNAT, "No matching port DNAT rule", true)
	return false
}

func (m *Manager) traceInbound1to1NAT(trace *PacketTrace, packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		trace.AddResult(StageInbound1to1NAT, "1:1 NAT not enabled", true)
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})

	translated := m.translateInboundReverse(packetData, d)
	if translated {
		m.dnatMutex.RLock()
		translatedIP, exists := m.dnatBiMap.getOriginal(srcIP)
		m.dnatMutex.RUnlock()

		if exists {
			msg := fmt.Sprintf("1:1 NAT reverse applied: %s -> %s", srcIP, translatedIP)
			trace.AddResult(StageInbound1to1NAT, msg, true)
			return true
		}
	}

	trace.AddResult(StageInbound1to1NAT, "No matching 1:1 NAT rule", true)
	return false
}

func (m *Manager) handleOutboundDNAT(trace *PacketTrace, packetData []byte, d *decoder) {
	m.traceOutbound1to1NAT(trace, packetData, d)
	m.traceOutboundPortReverse(trace, packetData, d)
}

func (m *Manager) traceOutbound1to1NAT(trace *PacketTrace, packetData []byte, d *decoder) bool {
	if !m.dnatEnabled.Load() {
		trace.AddResult(StageOutbound1to1NAT, "1:1 NAT not enabled", true)
		return false
	}

	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})

	translated := m.translateOutboundDNAT(packetData, d)
	if translated {
		m.dnatMutex.RLock()
		translatedIP, exists := m.dnatMappings[dstIP]
		m.dnatMutex.RUnlock()

		if exists {
			msg := fmt.Sprintf("1:1 NAT applied: %s -> %s", dstIP, translatedIP)
			trace.AddResult(StageOutbound1to1NAT, msg, true)
			return true
		}
	}

	trace.AddResult(StageOutbound1to1NAT, "No matching 1:1 NAT rule", true)
	return false
}

func (m *Manager) traceOutboundPortReverse(trace *PacketTrace, packetData []byte, d *decoder) bool {
	if !m.portDNATEnabled.Load() {
		trace.AddResult(StageOutboundPortReverse, "Port DNAT not enabled", true)
		return false
	}

	if len(packetData) < 20 || d.decoded[0] != layers.LayerTypeIPv4 {
		trace.AddResult(StageOutboundPortReverse, "Not IPv4, skipping port reverse", true)
		return false
	}

	if len(d.decoded) < 2 {
		trace.AddResult(StageOutboundPortReverse, "No transport layer, skipping port reverse", true)
		return false
	}

	srcIP := netip.AddrFrom4([4]byte{packetData[12], packetData[13], packetData[14], packetData[15]})
	dstIP := netip.AddrFrom4([4]byte{packetData[16], packetData[17], packetData[18], packetData[19]})

	var origPort uint16
	transport := d.decoded[1]
	switch transport {
	case layers.LayerTypeTCP:
		srcPort := uint16(d.tcp.SrcPort)
		dstPort := uint16(d.tcp.DstPort)
		conn, exists := m.tcpTracker.GetConnection(dstIP, dstPort, srcIP, srcPort)
		if exists {
			origPort = uint16(conn.DNATOrigPort.Load())
		}
		if origPort != 0 {
			msg := fmt.Sprintf("TCP DNAT reverse (tracked connection): %s:%d -> %s:%d", srcIP, srcPort, srcIP, origPort)
			trace.AddResult(StageOutboundPortReverse, msg, true)
			return true
		}
	case layers.LayerTypeUDP:
		srcPort := uint16(d.udp.SrcPort)
		dstPort := uint16(d.udp.DstPort)
		conn, exists := m.udpTracker.GetConnection(dstIP, dstPort, srcIP, srcPort)
		if exists {
			origPort = uint16(conn.DNATOrigPort.Load())
		}
		if origPort != 0 {
			msg := fmt.Sprintf("UDP DNAT reverse (tracked connection): %s:%d -> %s:%d", srcIP, srcPort, srcIP, origPort)
			trace.AddResult(StageOutboundPortReverse, msg, true)
			return true
		}
	default:
		trace.AddResult(StageOutboundPortReverse, "Not TCP/UDP, skipping port reverse", true)
		return false
	}

	trace.AddResult(StageOutboundPortReverse, "No tracked connection for DNAT reverse", true)
	return false
}

func (m *Manager) getDestPort(d *decoder) uint16 {
	if len(d.decoded) < 2 {
		return 0
	}
	switch d.decoded[1] {
	case layers.LayerTypeTCP:
		return uint16(d.tcp.DstPort)
	case layers.LayerTypeUDP:
		return uint16(d.udp.DstPort)
	default:
		return 0
	}
}
