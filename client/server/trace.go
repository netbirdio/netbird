package server

import (
	"context"
	"fmt"
	"net/netip"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

type packetTracer interface {
	TracePacketFromBuilder(builder *uspfilter.PacketBuilder) (*uspfilter.PacketTrace, error)
}

func (s *Server) TracePacket(_ context.Context, req *proto.TracePacketRequest) (*proto.TracePacketResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tracer, engine, err := s.getPacketTracer()
	if err != nil {
		return nil, err
	}

	srcAddr, err := s.parseAddress(req.GetSourceIp(), engine)
	if err != nil {
		return nil, fmt.Errorf("invalid source IP address: %w", err)
	}

	dstAddr, err := s.parseAddress(req.GetDestinationIp(), engine)
	if err != nil {
		return nil, fmt.Errorf("invalid destination IP address: %w", err)
	}

	protocol, err := s.parseProtocol(req.GetProtocol())
	if err != nil {
		return nil, err
	}

	direction, err := s.parseDirection(req.GetDirection())
	if err != nil {
		return nil, err
	}

	tcpState := s.parseTCPFlags(req.GetTcpFlags())

	builder := &uspfilter.PacketBuilder{
		SrcIP:     srcAddr,
		DstIP:     dstAddr,
		Protocol:  protocol,
		SrcPort:   uint16(req.GetSourcePort()),
		DstPort:   uint16(req.GetDestinationPort()),
		Direction: direction,
		TCPState:  tcpState,
		ICMPType:  uint8(req.GetIcmpType()),
		ICMPCode:  uint8(req.GetIcmpCode()),
	}

	trace, err := tracer.TracePacketFromBuilder(builder)
	if err != nil {
		return nil, fmt.Errorf("trace packet: %w", err)
	}

	return s.buildTraceResponse(trace), nil
}

func (s *Server) getPacketTracer() (packetTracer, *internal.Engine, error) {
	if s.connectClient == nil {
		return nil, nil, fmt.Errorf("connect client not initialized")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, nil, fmt.Errorf("engine not initialized")
	}

	fwManager := engine.GetFirewallManager()
	if fwManager == nil {
		return nil, nil, fmt.Errorf("firewall manager not initialized")
	}

	tracer, ok := fwManager.(packetTracer)
	if !ok {
		return nil, nil, fmt.Errorf("firewall manager does not support packet tracing")
	}

	return tracer, engine, nil
}

func (s *Server) parseAddress(addr string, engine *internal.Engine) (netip.Addr, error) {
	if addr == "self" {
		return engine.GetWgAddr(), nil
	}

	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	}

	return a.Unmap(), nil
}

func (s *Server) parseProtocol(protocol string) (fw.Protocol, error) {
	switch protocol {
	case "tcp":
		return fw.ProtocolTCP, nil
	case "udp":
		return fw.ProtocolUDP, nil
	case "icmp":
		return fw.ProtocolICMP, nil
	default:
		return "", fmt.Errorf("invalid protocol")
	}
}

func (s *Server) parseDirection(direction string) (fw.RuleDirection, error) {
	switch direction {
	case "in":
		return fw.RuleDirectionIN, nil
	case "out":
		return fw.RuleDirectionOUT, nil
	default:
		return 0, fmt.Errorf("invalid direction")
	}
}

func (s *Server) parseTCPFlags(flags *proto.TCPFlags) *uspfilter.TCPState {
	if flags == nil {
		return nil
	}

	return &uspfilter.TCPState{
		SYN: flags.GetSyn(),
		ACK: flags.GetAck(),
		FIN: flags.GetFin(),
		RST: flags.GetRst(),
		PSH: flags.GetPsh(),
		URG: flags.GetUrg(),
	}
}

func (s *Server) buildTraceResponse(trace *uspfilter.PacketTrace) *proto.TracePacketResponse {
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

	return resp
}
