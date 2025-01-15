package uspfilter

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

type PacketStage int

const (
	StageReceived PacketStage = iota
	StageConntrack
	StagePeerACL
	StageRouting
	StageRouteACL
	StageForwarding
	StageCompleted
)

const msgProcessingCompleted = "Processing completed"

func (s PacketStage) String() string {
	return map[PacketStage]string{
		StageReceived:   "Received",
		StageConntrack:  "Connection Tracking",
		StagePeerACL:    "Peer ACL",
		StageRouting:    "Routing",
		StageRouteACL:   "Route ACL",
		StageForwarding: "Forwarding",
		StageCompleted:  "Completed",
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
	SourceIP        net.IP
	DestinationIP   net.IP
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
	SrcIP       net.IP
	DstIP       net.IP
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
		SrcIP:    p.SrcIP,
		DstIP:    p.DstIP,
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

func (m *Manager) traceInbound(packetData []byte, trace *PacketTrace, d *decoder, srcIP net.IP, dstIP net.IP) *PacketTrace {
	if m.stateful && m.handleConntrackState(trace, d, srcIP, dstIP) {
		return trace
	}

	if m.handleLocalDelivery(trace, packetData, d, srcIP, dstIP) {
		return trace
	}

	if !m.handleRouting(trace) {
		return trace
	}

	if m.nativeRouter {
		return m.handleNativeRouter(trace)
	}

	return m.handleRouteACLs(trace, d, srcIP, dstIP)
}

func (m *Manager) handleConntrackState(trace *PacketTrace, d *decoder, srcIP, dstIP net.IP) bool {
	allowed := m.isValidTrackedConnection(d, srcIP, dstIP)
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

func (m *Manager) handleLocalDelivery(trace *PacketTrace, packetData []byte, d *decoder, srcIP, dstIP net.IP) bool {
	if !m.localForwarding {
		trace.AddResult(StageRouting, "Local forwarding disabled", false)
		trace.AddResult(StageCompleted, "Packet dropped - local forwarding disabled", false)
		return true
	}

	trace.AddResult(StageRouting, "Packet destined for local delivery", true)
	blocked := m.peerACLsBlock(srcIP, packetData, m.incomingRules, d)

	msg := "Allowed by peer ACL rules"
	if blocked {
		msg = "Blocked by peer ACL rules"
	}
	trace.AddResult(StagePeerACL, msg, !blocked)

	if m.netstack {
		m.addForwardingResult(trace, "proxy-local", "127.0.0.1", !blocked)
	}

	trace.AddResult(StageCompleted, msgProcessingCompleted, !blocked)
	return true
}

func (m *Manager) handleRouting(trace *PacketTrace) bool {
	if !m.routingEnabled {
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

func (m *Manager) handleRouteACLs(trace *PacketTrace, d *decoder, srcIP, dstIP net.IP) *PacketTrace {
	proto := getProtocolFromPacket(d)
	srcPort, dstPort := getPortsFromPacket(d)
	allowed := m.routeACLsPass(srcIP, dstIP, proto, srcPort, dstPort)

	msg := "Allowed by route ACLs"
	if !allowed {
		msg = "Blocked by route ACLs"
	}
	trace.AddResult(StageRouteACL, msg, allowed)

	if allowed && m.forwarder != nil {
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
	// will create or update the connection state
	dropped := m.processOutgoingHooks(packetData)
	if dropped {
		trace.AddResult(StageCompleted, "Packet dropped by outgoing hook", false)
	} else {
		trace.AddResult(StageCompleted, "Packet allowed (outgoing)", true)
	}
	return trace
}
