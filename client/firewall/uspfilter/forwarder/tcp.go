package forwarder

import (
	"net"
	"strconv"

	"github.com/google/uuid"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/util/netrelay"
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

	dialAddr := net.JoinHostPort(f.determineDialAddr(id.LocalAddress).String(), strconv.Itoa(int(id.LocalPort)))

	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		if f.logger.Enabled(nblog.LevelTrace) {
			f.logger.Trace2("forwarder: dial error for %v: %v", epID(id), err)
		}
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
	if f.logger.Enabled(nblog.LevelTrace) {
		f.logger.Trace1("forwarder: established TCP connection %v", epID(id))
	}

	go f.proxyTCP(id, inConn, outConn, ep, flowID)
}

func (f *Forwarder) proxyTCP(id stack.TransportEndpointID, inConn *gonet.TCPConn, outConn net.Conn, ep tcpip.Endpoint, flowID uuid.UUID) {
	// netrelay.Relay copies bidirectionally with proper half-close propagation
	// and fully closes both conns before returning.
	bytesFromInToOut, bytesFromOutToIn := netrelay.Relay(f.ctx, inConn, outConn, netrelay.Options{
		Logger: f.logger,
	})

	// Close the netstack endpoint after both conns are drained.
	ep.Close()

	var rxPackets, txPackets uint64
	if tcpStats, ok := ep.Stats().(*tcp.Stats); ok {
		// fields are flipped since this is the in conn
		rxPackets = tcpStats.SegmentsSent.Value()
		txPackets = tcpStats.SegmentsReceived.Value()
	}

	if f.logger.Enabled(nblog.LevelTrace) {
		f.logger.Trace5("forwarder: Removed TCP connection %s [in: %d Pkts/%d B, out: %d Pkts/%d B]", epID(id), rxPackets, bytesFromOutToIn, txPackets, bytesFromInToOut)
	}

	f.sendTCPEvent(nftypes.TypeEnd, flowID, id, uint64(bytesFromOutToIn), uint64(bytesFromInToOut), rxPackets, txPackets)
}

func (f *Forwarder) sendTCPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, rxBytes, txBytes, rxPackets, txPackets uint64) {
	srcIp := addrToNetipAddr(id.RemoteAddress)
	dstIp := addrToNetipAddr(id.LocalAddress)

	fields := nftypes.EventFields{
		FlowID:     flowID,
		Type:       typ,
		Direction:  nftypes.Ingress,
		Protocol:   nftypes.TCP,
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
