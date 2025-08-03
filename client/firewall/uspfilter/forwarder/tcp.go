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

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// handleTCP is called by the TCP forwarder for new connections.
func (f *Forwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

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

	// Create wait queue for blocking syscalls
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

	// Complete the handshake
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
		// Close connections and endpoint.
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
