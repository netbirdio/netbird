package forwarder

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/uuid"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// handleICMP handles ICMP packets from the network stack
func (f *Forwarder) handleICMP(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	icmpHdr := header.ICMPv4(pkt.TransportHeader().View().AsSlice())

	flowID := uuid.New()
	f.sendICMPEvent(nftypes.TypeStart, flowID, id, uint8(icmpHdr.Type()), uint8(icmpHdr.Code()), 0, 0)

	// For Echo Requests, send and wait for response
	if icmpHdr.Type() == header.ICMPv4Echo {
		return f.handleICMPEcho(flowID, id, pkt, uint8(icmpHdr.Type()), uint8(icmpHdr.Code()))
	}

	// For other ICMP types (Time Exceeded, Destination Unreachable, etc), forward without waiting
	if !f.hasRawICMPAccess {
		f.logger.Debug2("forwarder: Cannot handle ICMP type %v without raw socket access for %v", icmpHdr.Type(), epID(id))
		return false
	}

	icmpData := stack.PayloadSince(pkt.TransportHeader()).AsSlice()
	conn, err := f.forwardICMPPacket(id, icmpData, uint8(icmpHdr.Type()), uint8(icmpHdr.Code()), 100*time.Millisecond)
	if err != nil {
		f.logger.Error2("forwarder: Failed to forward ICMP packet for %v: %v", epID(id), err)
		return true
	}
	if err := conn.Close(); err != nil {
		f.logger.Debug1("forwarder: Failed to close ICMP socket: %v", err)
	}

	return true
}

// handleICMPEcho handles ICMP echo requests asynchronously with rate limiting.
func (f *Forwarder) handleICMPEcho(flowID uuid.UUID, id stack.TransportEndpointID, pkt *stack.PacketBuffer, icmpType, icmpCode uint8) bool {
	select {
	case f.pingSemaphore <- struct{}{}:
		icmpData := stack.PayloadSince(pkt.TransportHeader()).ToSlice()
		rxBytes := pkt.Size()

		go func() {
			defer func() { <-f.pingSemaphore }()

			if f.hasRawICMPAccess {
				f.handleICMPViaSocket(flowID, id, icmpType, icmpCode, icmpData, rxBytes)
			} else {
				f.handleICMPViaPing(flowID, id, icmpType, icmpCode, icmpData, rxBytes)
			}
		}()
	default:
		f.logger.Debug3("forwarder: ICMP rate limit exceeded for %v type %v code %v",
			epID(id), icmpType, icmpCode)
	}
	return true
}

// forwardICMPPacket creates a raw ICMP socket and sends the packet, returning the connection.
// The caller is responsible for closing the returned connection.
func (f *Forwarder) forwardICMPPacket(id stack.TransportEndpointID, payload []byte, icmpType, icmpCode uint8, timeout time.Duration) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(f.ctx, timeout)
	defer cancel()

	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("create ICMP socket: %w", err)
	}

	dstIP := f.determineDialAddr(id.LocalAddress)
	dst := &net.IPAddr{IP: dstIP}

	if _, err = conn.WriteTo(payload, dst); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			f.logger.Debug1("forwarder: Failed to close ICMP socket: %v", closeErr)
		}
		return nil, fmt.Errorf("write ICMP packet: %w", err)
	}

	f.logger.Trace3("forwarder: Forwarded ICMP packet %v type %v code %v",
		epID(id), icmpType, icmpCode)

	return conn, nil
}

// handleICMPViaSocket handles ICMP echo requests using raw sockets.
func (f *Forwarder) handleICMPViaSocket(flowID uuid.UUID, id stack.TransportEndpointID, icmpType, icmpCode uint8, icmpData []byte, rxBytes int) {
	sendTime := time.Now()

	conn, err := f.forwardICMPPacket(id, icmpData, icmpType, icmpCode, 5*time.Second)
	if err != nil {
		f.logger.Error2("forwarder: Failed to send ICMP packet for %v: %v", epID(id), err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			f.logger.Debug1("forwarder: Failed to close ICMP socket: %v", err)
		}
	}()

	txBytes := f.handleEchoResponse(conn, id)
	rtt := time.Since(sendTime).Round(10 * time.Microsecond)

	f.logger.Trace4("forwarder: Forwarded ICMP echo reply %v type %v code %v (rtt=%v, raw socket)",
		epID(id), icmpType, icmpCode, rtt)

	f.sendICMPEvent(nftypes.TypeEnd, flowID, id, icmpType, icmpCode, uint64(rxBytes), uint64(txBytes))
}

func (f *Forwarder) handleEchoResponse(conn net.PacketConn, id stack.TransportEndpointID) int {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		f.logger.Error1("forwarder: Failed to set read deadline for ICMP response: %v", err)
		return 0
	}

	response := make([]byte, f.endpoint.mtu.Load())
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		if !isTimeout(err) {
			f.logger.Error1("forwarder: Failed to read ICMP response: %v", err)
		}
		return 0
	}

	return f.injectICMPReply(id, response[:n])
}

// sendICMPEvent stores flow events for ICMP packets
func (f *Forwarder) sendICMPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, icmpType, icmpCode uint8, rxBytes, txBytes uint64) {
	var rxPackets, txPackets uint64
	if rxBytes > 0 {
		rxPackets = 1
	}
	if txBytes > 0 {
		txPackets = 1
	}

	srcIp := netip.AddrFrom4(id.RemoteAddress.As4())
	dstIp := netip.AddrFrom4(id.LocalAddress.As4())

	fields := nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.ICMP,
		// TODO: handle ipv6
		SourceIP: srcIp,
		DestIP:   dstIp,
		ICMPType: icmpType,
		ICMPCode: icmpCode,

		RxBytes:   rxBytes,
		TxBytes:   txBytes,
		RxPackets: rxPackets,
		TxPackets: txPackets,
	}

	if typ == nftypes.TypeStart {
		if ruleId, ok := f.getRuleID(srcIp, dstIp, id.RemotePort, id.LocalPort); ok {
			fields.RuleID = ruleId
		}
	} else {
		f.DeleteRuleID(srcIp, dstIp, id.RemotePort, id.LocalPort)
	}

	f.flowLogger.StoreEvent(fields)
}

// handleICMPViaPing handles ICMP echo requests by executing the system ping binary.
// This is used as a fallback when raw socket access is not available.
func (f *Forwarder) handleICMPViaPing(flowID uuid.UUID, id stack.TransportEndpointID, icmpType, icmpCode uint8, icmpData []byte, rxBytes int) {
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()

	dstIP := f.determineDialAddr(id.LocalAddress)
	cmd := buildPingCommand(ctx, dstIP, 5*time.Second)

	pingStart := time.Now()
	if err := cmd.Run(); err != nil {
		f.logger.Warn4("forwarder: Ping binary failed for %v type %v code %v: %v", epID(id),
			icmpType, icmpCode, err)
		return
	}
	rtt := time.Since(pingStart).Round(10 * time.Microsecond)

	f.logger.Trace3("forwarder: Forwarded ICMP echo request %v type %v code %v",
		epID(id), icmpType, icmpCode)

	txBytes := f.synthesizeEchoReply(id, icmpData)

	f.logger.Trace4("forwarder: Forwarded ICMP echo reply %v type %v code %v (rtt=%v, ping binary)",
		epID(id), icmpType, icmpCode, rtt)

	f.sendICMPEvent(nftypes.TypeEnd, flowID, id, icmpType, icmpCode, uint64(rxBytes), uint64(txBytes))
}

// buildPingCommand creates a platform-specific ping command.
func buildPingCommand(ctx context.Context, target net.IP, timeout time.Duration) *exec.Cmd {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	switch runtime.GOOS {
	case "linux", "android":
		return exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), "-q", target.String())
	case "darwin", "ios":
		return exec.CommandContext(ctx, "ping", "-c", "1", "-t", fmt.Sprintf("%d", timeoutSec), "-q", target.String())
	case "freebsd":
		return exec.CommandContext(ctx, "ping", "-c", "1", "-t", fmt.Sprintf("%d", timeoutSec), target.String())
	case "openbsd", "netbsd":
		return exec.CommandContext(ctx, "ping", "-c", "1", "-w", fmt.Sprintf("%d", timeoutSec), target.String())
	case "windows":
		return exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutSec*1000), target.String())
	default:
		return exec.CommandContext(ctx, "ping", "-c", "1", target.String())
	}
}

// synthesizeEchoReply creates an ICMP echo reply from raw ICMP data and injects it back into the network stack.
// Returns the size of the injected packet.
func (f *Forwarder) synthesizeEchoReply(id stack.TransportEndpointID, icmpData []byte) int {
	replyICMP := make([]byte, len(icmpData))
	copy(replyICMP, icmpData)

	replyICMPHdr := header.ICMPv4(replyICMP)
	replyICMPHdr.SetType(header.ICMPv4EchoReply)
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(header.ICMPv4Checksum(replyICMPHdr, 0))

	return f.injectICMPReply(id, replyICMP)
}

// injectICMPReply wraps an ICMP payload in an IP header and injects it into the network stack.
// Returns the total size of the injected packet, or 0 if injection failed.
func (f *Forwarder) injectICMPReply(id stack.TransportEndpointID, icmpPayload []byte) int {
	ipHdr := make([]byte, header.IPv4MinimumSize)
	ip := header.IPv4(ipHdr)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + len(icmpPayload)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     id.LocalAddress,
		DstAddr:     id.RemoteAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	fullPacket := make([]byte, 0, len(ipHdr)+len(icmpPayload))
	fullPacket = append(fullPacket, ipHdr...)
	fullPacket = append(fullPacket, icmpPayload...)

	// Bypass netstack and send directly to peer to avoid looping through our ICMP handler
	if err := f.endpoint.device.CreateOutboundPacket(fullPacket, id.RemoteAddress.AsSlice()); err != nil {
		f.logger.Error1("forwarder: Failed to send ICMP reply to peer: %v", err)
		return 0
	}

	return len(fullPacket)
}
