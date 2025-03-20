package forwarder

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// handleICMP handles ICMP packets from the network stack
func (f *Forwarder) handleICMP(id stack.TransportEndpointID, pkt stack.PacketBufferPtr) bool {
	icmpHdr := header.ICMPv4(pkt.TransportHeader().View().AsSlice())
	icmpType := uint8(icmpHdr.Type())
	icmpCode := uint8(icmpHdr.Code())

	if header.ICMPv4Type(icmpType) == header.ICMPv4EchoReply {
		// dont process our own replies
		return true
	}

	flowID := uuid.New()
	f.sendICMPEvent(nftypes.TypeStart, flowID, id, icmpType, icmpCode)

	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()

	lc := net.ListenConfig{}
	// TODO: support non-root
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		f.logger.Error("Failed to create ICMP socket for %v: %v", epID(id), err)

		// This will make netstack reply on behalf of the original destination, that's ok for now
		return false
	}
	defer func() {
		if err := conn.Close(); err != nil {
			f.logger.Debug("Failed to close ICMP socket: %v", err)
		}
	}()

	dstIP := f.determineDialAddr(id.LocalAddress)
	dst := &net.IPAddr{IP: dstIP}

	fullPacket := stack.PayloadSince(pkt.TransportHeader())
	payload := fullPacket.AsSlice()

	if _, err = conn.WriteTo(payload, dst); err != nil {
		f.logger.Error("Failed to write ICMP packet for %v: %v", epID(id), err)
		return true
	}

	f.logger.Trace("Forwarded ICMP packet %v type %v code %v",
		epID(id), icmpHdr.Type(), icmpHdr.Code())

	// For Echo Requests, send and handle response
	if header.ICMPv4Type(icmpType) == header.ICMPv4Echo {
		f.handleEchoResponse(icmpHdr, conn, id)
		f.sendICMPEvent(nftypes.TypeEnd, flowID, id, icmpType, icmpCode)
	}

	// For other ICMP types (Time Exceeded, Destination Unreachable, etc) do nothing
	return true
}

func (f *Forwarder) handleEchoResponse(icmpHdr header.ICMPv4, conn net.PacketConn, id stack.TransportEndpointID) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		f.logger.Error("Failed to set read deadline for ICMP response: %v", err)
		return
	}

	response := make([]byte, f.endpoint.mtu)
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		if !isTimeout(err) {
			f.logger.Error("Failed to read ICMP response: %v", err)
		}
		return
	}

	ipHdr := make([]byte, header.IPv4MinimumSize)
	ip := header.IPv4(ipHdr)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + n),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     id.LocalAddress,
		DstAddr:     id.RemoteAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	fullPacket := make([]byte, 0, len(ipHdr)+n)
	fullPacket = append(fullPacket, ipHdr...)
	fullPacket = append(fullPacket, response[:n]...)

	if err := f.InjectIncomingPacket(fullPacket); err != nil {
		f.logger.Error("Failed to inject ICMP response: %v", err)

		return
	}

	f.logger.Trace("Forwarded ICMP echo reply for %v type %v code %v",
		epID(id), icmpHdr.Type(), icmpHdr.Code())
}

// sendICMPEvent stores flow events for ICMP packets
func (f *Forwarder) sendICMPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, icmpType, icmpCode uint8) {
	f.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.ICMP,
		// TODO: handle ipv6
		SourceIP: netip.AddrFrom4(id.RemoteAddress.As4()),
		DestIP:   netip.AddrFrom4(id.LocalAddress.As4()),
		ICMPType: icmpType,
		ICMPCode: icmpCode,

		// TODO: get packets/bytes
	})
}
