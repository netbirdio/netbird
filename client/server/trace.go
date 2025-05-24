package server

import (
	"context"
	"fmt"
	"net/netip"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/proto"
)

type packetTracer interface {
	TracePacketFromBuilder(builder *uspfilter.PacketBuilder) (*uspfilter.PacketTrace, error)
}

func (s *Server) TracePacket(_ context.Context, req *proto.TracePacketRequest) (*proto.TracePacketResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.connectClient == nil {
		return nil, fmt.Errorf("connect client not initialized")
	}
	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	fwManager := engine.GetFirewallManager()
	if fwManager == nil {
		return nil, fmt.Errorf("firewall manager not initialized")
	}

	tracer, ok := fwManager.(packetTracer)
	if !ok {
		return nil, fmt.Errorf("firewall manager does not support packet tracing")
	}

	srcAddr, err := netip.ParseAddr(req.GetSourceIp())
	if err != nil {
		return nil, fmt.Errorf("invalid source IP address: %w", err)
	}
	if req.GetSourceIp() == "self" {
		srcAddr = engine.GetWgAddr()
	}
	srcAddr = srcAddr.Unmap()

	dstAddr, err := netip.ParseAddr(req.GetDestinationIp())
	if err != nil {
		return nil, fmt.Errorf("invalid destination IP address: %w", err)
	}
	if req.GetDestinationIp() == "self" {
		dstAddr = engine.GetWgAddr()
	}
	dstAddr = dstAddr.Unmap()

	var tcpState *uspfilter.TCPState
	if flags := req.GetTcpFlags(); flags != nil {
		tcpState = &uspfilter.TCPState{
			SYN: flags.GetSyn(),
			ACK: flags.GetAck(),
			FIN: flags.GetFin(),
			RST: flags.GetRst(),
			PSH: flags.GetPsh(),
			URG: flags.GetUrg(),
		}
	}

	var dir fw.RuleDirection
	switch req.GetDirection() {
	case "in":
		dir = fw.RuleDirectionIN
	case "out":
		dir = fw.RuleDirectionOUT
	default:
		return nil, fmt.Errorf("invalid direction")
	}

	var protocol fw.Protocol
	switch req.GetProtocol() {
	case "tcp":
		protocol = fw.ProtocolTCP
	case "udp":
		protocol = fw.ProtocolUDP
	case "icmp":
		protocol = fw.ProtocolICMP
	default:
		return nil, fmt.Errorf("invalid protocolcol")
	}

	builder := &uspfilter.PacketBuilder{
		SrcIP:     srcAddr,
		DstIP:     dstAddr,
		Protocol:  protocol,
		SrcPort:   uint16(req.GetSourcePort()),
		DstPort:   uint16(req.GetDestinationPort()),
		Direction: dir,
		TCPState:  tcpState,
		ICMPType:  uint8(req.GetIcmpType()),
		ICMPCode:  uint8(req.GetIcmpCode()),
	}
	trace, err := tracer.TracePacketFromBuilder(builder)
	if err != nil {
		return nil, fmt.Errorf("trace packet: %w", err)
	}

	resp := &proto.TracePacketResponse{}

	for _, result := range trace.Results {
		stage := &proto.TraceStage{
			Name:    result.Stage.String(),
			Message: result.Message,
			Allowed: result.Allowed,
		}
		if result.ForwarderAction != nil {
			details := fmt.Sprintf("%s to %s", result.ForwarderAction.Action, result.ForwarderAction.RemoteAddr)
			stage.ForwardingDetails = &details
		}
		resp.Stages = append(resp.Stages, stage)
	}

	if len(trace.Results) > 0 {
		resp.FinalDisposition = trace.Results[len(trace.Results)-1].Allowed
	}

	return resp, nil
}
