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

	srcAddr, dstAddr, err := s.resolveTraceAddresses(req.GetSourceIp(), req.GetDestinationIp(), engine)
	if err != nil {
		return nil, err
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

// resolveTraceAddresses parses src/dst, resolving "self" to the local overlay
// address matching the peer's address family.
func (s *Server) resolveTraceAddresses(src, dst string, engine *internal.Engine) (netip.Addr, netip.Addr, error) {
	srcSelf := src == "self"
	dstSelf := dst == "self"

	if srcSelf && dstSelf {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("both source and destination cannot be 'self'")
	}

	var srcAddr, dstAddr netip.Addr
	var err error

	// Parse the non-self address first so we know the family for self resolution.
	if !srcSelf {
		if srcAddr, err = parseAddr(src); err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid source IP: %w", err)
		}
	}
	if !dstSelf {
		if dstAddr, err = parseAddr(dst); err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid destination IP: %w", err)
		}
	}

	// Determine the peer address to pick the right self address.
	peer := srcAddr
	if srcSelf {
		peer = dstAddr
	}

	if srcSelf {
		if srcAddr, err = selfAddr(engine, peer); err != nil {
			return netip.Addr{}, netip.Addr{}, err
		}
	}
	if dstSelf {
		if dstAddr, err = selfAddr(engine, peer); err != nil {
			return netip.Addr{}, netip.Addr{}, err
		}
	}

	return srcAddr, dstAddr, nil
}

func selfAddr(engine *internal.Engine, peer netip.Addr) (netip.Addr, error) {
	var addr netip.Addr
	if peer.Is6() {
		addr = engine.GetWgV6Addr()
	} else {
		addr = engine.GetWgAddr()
	}
	if !addr.IsValid() {
		family := "IPv4"
		if peer.Is6() {
			family = "IPv6"
		}
		return netip.Addr{}, fmt.Errorf("no local %s overlay address configured", family)
	}
	return addr, nil
}

func parseAddr(addr string) (netip.Addr, error) {
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
