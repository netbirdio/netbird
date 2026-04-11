package forwarder

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/google/uuid"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/netbirdio/netbird/client/inspect"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// handleTCP is called by the TCP forwarder for new connections.
func (f *Forwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	// If the inspection engine is configured, accept the connection first and hand it off.
	if p := f.proxy.Load(); p != nil {
		f.handleTCPWithInspection(r, id, p)
		return
	}

	f.handleTCPDirect(r, id)
}

// handleTCPWithInspection accepts the connection and hands it to the inspection
// engine. For allow decisions, the forwarder does its own relay (passthrough).
// For block/inspect, the engine handles everything internally.
func (f *Forwarder) handleTCPWithInspection(r *tcp.ForwarderRequest, id stack.TransportEndpointID, p *inspect.Proxy) {
	flowID := uuid.New()
	f.sendTCPEvent(nftypes.TypeStart, flowID, id, 0, 0, 0, 0)

	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		f.logger.Error1("forwarder: create TCP endpoint for inspection: %v", epErr)
		r.Complete(true)
		f.sendTCPEvent(nftypes.TypeEnd, flowID, id, 0, 0, 0, 0)
		return
	}
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	srcIP := netip.AddrFrom4(id.RemoteAddress.As4())
	dstIP := netip.AddrFrom4(id.LocalAddress.As4())
	dst := netip.AddrPortFrom(dstIP, id.LocalPort)

	var policyID []byte
	if ruleID, ok := f.getRuleID(srcIP, dstIP, id.RemotePort, id.LocalPort); ok {
		policyID = ruleID
	}

	src := inspect.SourceInfo{
		IP:       srcIP,
		PolicyID: inspect.PolicyID(policyID),
	}

	f.logger.Trace1("forwarder: handing TCP %v to inspection engine", epID(id))

	go func() {
		result, err := p.InspectTCP(f.ctx, inConn, dst, src)
		if err != nil && err != inspect.ErrBlocked {
			f.logger.Debug2("forwarder: inspection error for %v: %v", epID(id), err)
		}

		// Passthrough: engine returned allow, forwarder does the relay.
		if result.PassthroughConn != nil {
			dialAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)
			outConn, dialErr := (&net.Dialer{}).DialContext(f.ctx, "tcp", dialAddr)
			if dialErr != nil {
				f.logger.Trace2("forwarder: passthrough dial error for %v: %v", epID(id), dialErr)
				if closeErr := result.PassthroughConn.Close(); closeErr != nil {
					f.logger.Debug1("forwarder: close passthrough conn: %v", closeErr)
				}
				ep.Close()
				f.sendTCPEvent(nftypes.TypeEnd, flowID, id, 0, 0, 0, 0)
				return
			}
			f.proxyTCPPassthrough(id, result.PassthroughConn, outConn, ep, flowID)
			return
		}

		// Engine handled it (block/inspect/HTTP). Capture stats and clean up.
		var rxPackets, txPackets uint64
		if tcpStats, ok := ep.Stats().(*tcp.Stats); ok {
			rxPackets = tcpStats.SegmentsSent.Value()
			txPackets = tcpStats.SegmentsReceived.Value()
		}
		ep.Close()
		f.sendTCPEvent(nftypes.TypeEnd, flowID, id, 0, 0, rxPackets, txPackets)
	}()
}

// handleTCPDirect handles TCP connections with direct relay (no proxy).
func (f *Forwarder) handleTCPDirect(r *tcp.ForwarderRequest, id stack.TransportEndpointID) {
	flowID := uuid.New()

	f.sendTCPEvent(nftypes.TypeStart, flowID, id, 0, 0, 0, 0)
	var success bool
	defer func() {
		if !success {
			f.sendTCPEvent(nftypes.TypeEnd, flowID, id, 0, 0, 0, 0)
		}
	}()

	dialAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)

	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		f.logger.Trace2("forwarder: dial error for %v: %v", epID(id), err)
		return
	}

	wq := waiter.Queue{}

	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		f.logger.Error1("forwarder: failed to create TCP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			f.logger.Debug1("forwarder: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	success = true
	f.logger.Trace1("forwarder: established TCP connection %v", epID(id))

	go f.proxyTCP(id, inConn, outConn, ep, flowID)
}

func (f *Forwarder) proxyTCP(id stack.TransportEndpointID, inConn *gonet.TCPConn, outConn net.Conn, ep tcpip.Endpoint, flowID uuid.UUID) {

	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		if err := inConn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug1("forwarder: inConn close error: %v", err)
		}
		if err := outConn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug1("forwarder: outConn close error: %v", err)
		}

		ep.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var (
		bytesFromInToOut int64 // bytes from client to server (tx for client)
		bytesFromOutToIn int64 // bytes from server to client (rx for client)
		errInToOut       error
		errOutToIn       error
	)

	go func() {
		bytesFromInToOut, errInToOut = io.Copy(outConn, inConn)
		cancel()
		wg.Done()
	}()

	go func() {

		bytesFromOutToIn, errOutToIn = io.Copy(inConn, outConn)
		cancel()
		wg.Done()
	}()

	wg.Wait()

	if errInToOut != nil {
		if !isClosedError(errInToOut) {
			f.logger.Error2("proxyTCP: copy error (in → out) for %s: %v", epID(id), errInToOut)
		}
	}
	if errOutToIn != nil {
		if !isClosedError(errOutToIn) {
			f.logger.Error2("proxyTCP: copy error (out → in) for %s: %v", epID(id), errOutToIn)
		}
	}

	var rxPackets, txPackets uint64
	if tcpStats, ok := ep.Stats().(*tcp.Stats); ok {
		// fields are flipped since this is the in conn
		rxPackets = tcpStats.SegmentsSent.Value()
		txPackets = tcpStats.SegmentsReceived.Value()
	}

	f.logger.Trace5("forwarder: Removed TCP connection %s [in: %d Pkts/%d B, out: %d Pkts/%d B]", epID(id), rxPackets, bytesFromOutToIn, txPackets, bytesFromInToOut)

	f.sendTCPEvent(nftypes.TypeEnd, flowID, id, uint64(bytesFromOutToIn), uint64(bytesFromInToOut), rxPackets, txPackets)
}

// proxyTCPPassthrough relays traffic between a peeked inbound connection
// (from the inspection engine passthrough) and the outbound connection.
// It accepts net.Conn for inConn since the inspection engine wraps it in a peekConn.
func (f *Forwarder) proxyTCPPassthrough(id stack.TransportEndpointID, inConn net.Conn, outConn net.Conn, ep tcpip.Endpoint, flowID uuid.UUID) {
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		if err := inConn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug1("forwarder: passthrough inConn close: %v", err)
		}
		if err := outConn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug1("forwarder: passthrough outConn close: %v", err)
		}
		ep.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var (
		bytesIn  int64
		bytesOut int64
		errIn    error
		errOut   error
	)

	go func() {
		bytesIn, errIn = io.Copy(outConn, inConn)
		cancel()
		wg.Done()
	}()

	go func() {
		bytesOut, errOut = io.Copy(inConn, outConn)
		cancel()
		wg.Done()
	}()

	wg.Wait()

	if errIn != nil && !isClosedError(errIn) {
		f.logger.Error2("proxyTCPPassthrough: copy error (in→out) for %s: %v", epID(id), errIn)
	}
	if errOut != nil && !isClosedError(errOut) {
		f.logger.Error2("proxyTCPPassthrough: copy error (out→in) for %s: %v", epID(id), errOut)
	}

	var rxPackets, txPackets uint64
	if tcpStats, ok := ep.Stats().(*tcp.Stats); ok {
		rxPackets = tcpStats.SegmentsSent.Value()
		txPackets = tcpStats.SegmentsReceived.Value()
	}

	f.logger.Trace5("forwarder: passthrough TCP %s [in: %d Pkts/%d B, out: %d Pkts/%d B]", epID(id), rxPackets, bytesOut, txPackets, bytesIn)

	f.sendTCPEvent(nftypes.TypeEnd, flowID, id, uint64(bytesOut), uint64(bytesIn), rxPackets, txPackets)
}

func (f *Forwarder) sendTCPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, rxBytes, txBytes, rxPackets, txPackets uint64) {
	srcIp := netip.AddrFrom4(id.RemoteAddress.As4())
	dstIp := netip.AddrFrom4(id.LocalAddress.As4())

	fields := nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.TCP,
		// TODO: handle ipv6
		SourceIP:   srcIp,
		DestIP:     dstIp,
		SourcePort: id.RemotePort,
		DestPort:   id.LocalPort,
		RxBytes:    rxBytes,
		TxBytes:    txBytes,
		RxPackets:  rxPackets,
		TxPackets:  txPackets,
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
