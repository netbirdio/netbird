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

	f.sendTCPEvent(nftypes.TypeStart, flowID, id, nil, 0, 0)
	var success bool
	defer func() {
		if !success {
			f.sendTCPEvent(nftypes.TypeEnd, flowID, id, nil, 0, 0)
		}
	}()

	dialAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)

	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		f.logger.Trace("forwarder: dial error for %v: %v", epID(id), err)
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		f.logger.Error("forwarder: failed to create TCP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			f.logger.Debug("forwarder: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	// Complete the handshake
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	success = true
	f.logger.Trace("forwarder: established TCP connection %v", epID(id))

	go f.proxyTCP(id, inConn, outConn, ep, flowID)
}

func (f *Forwarder) proxyTCP(id stack.TransportEndpointID, inConn *gonet.TCPConn, outConn net.Conn, ep tcpip.Endpoint, flowID uuid.UUID) {

	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		inConn.Close()
		outConn.Close()
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
		defer wg.Done()
		var n int64
		n, errInToOut = io.Copy(outConn, inConn)
		bytesFromInToOut = n
	}()

	go func() {
		defer wg.Done()
		var n int64
		n, errOutToIn = io.Copy(inConn, outConn)
		bytesFromOutToIn = n
	}()

	wg.Wait()

	if errInToOut != nil {
		if !isClosedError(errInToOut) {
			f.logger.Error("proxyTCP: copy error (in -> out): %v", errInToOut)
		}
		f.logger.Trace("forwarder: tearing down TCP connection %v", epID(id))
	}
	if errOutToIn != nil {
		if !isClosedError(errOutToIn) {
			f.logger.Error("proxyTCP: copy error (out -> in): %v", errOutToIn)
		}
		f.logger.Trace("forwarder: tearing down TCP connection %v", epID(id))
	}

	// Close connections and endpoint.
	if err := inConn.Close(); err != nil {
		f.logger.Debug("forwarder: inConn close error: %v", err)
	}
	if err := outConn.Close(); err != nil {
		f.logger.Debug("forwarder: outConn close error: %v", err)
	}
	ep.Close()

	f.sendTCPEvent(nftypes.TypeEnd, flowID, id, ep, uint64(bytesFromOutToIn), uint64(bytesFromInToOut))
}

func (f *Forwarder) sendTCPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, ep tcpip.Endpoint, rxBytes, txBytes uint64) {
	fields := nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.TCP,
		// TODO: handle ipv6
		SourceIP:   netip.AddrFrom4(id.RemoteAddress.As4()),
		DestIP:     netip.AddrFrom4(id.LocalAddress.As4()),
		SourcePort: id.RemotePort,
		DestPort:   id.LocalPort,
		RxBytes:    rxBytes,
		TxBytes:    txBytes,
	}

	if ep != nil {
		if tcpStats, ok := ep.Stats().(*tcp.Stats); ok {
			// fields are flipped since this is the in conn
			// TODO: get bytes
			fields.RxPackets = tcpStats.SegmentsSent.Value()
			fields.TxPackets = tcpStats.SegmentsReceived.Value()
		}
	}

	remoteIp, _ := netip.ParseAddr(id.RemoteAddress.String())
	localIp, _ := netip.ParseAddr(id.LocalAddress.String())

	if ruleId, ok := f.getRuleID(typ, remoteIp, localIp, id.RemotePort, id.LocalPort); ok {
		fields.RuleID = ruleId
	}

	f.flowLogger.StoreEvent(fields)
}
