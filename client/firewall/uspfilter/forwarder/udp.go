package forwarder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	udpTimeout = 30 * time.Second
)

type udpPacketConn struct {
	conn     *gonet.UDPConn
	outConn  net.Conn
	lastSeen atomic.Int64
	cancel   context.CancelFunc
	ep       tcpip.Endpoint
	flowID   uuid.UUID
}

type udpForwarder struct {
	sync.RWMutex
	logger     *nblog.Logger
	flowLogger nftypes.FlowLogger
	conns      map[stack.TransportEndpointID]*udpPacketConn
	bufPool    sync.Pool
	ctx        context.Context
	cancel     context.CancelFunc
}

type idleConn struct {
	id   stack.TransportEndpointID
	conn *udpPacketConn
}

func newUDPForwarder(mtu uint16, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *udpForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	f := &udpForwarder{
		logger:     logger,
		flowLogger: flowLogger,
		conns:      make(map[stack.TransportEndpointID]*udpPacketConn),
		ctx:        ctx,
		cancel:     cancel,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, mtu)
				return &b
			},
		},
	}
	go f.cleanup()
	return f
}

// Stop stops the UDP forwarder and all active connections
func (f *udpForwarder) Stop() {
	f.cancel()

	f.Lock()
	defer f.Unlock()

	for id, conn := range f.conns {
		conn.cancel()
		if err := conn.conn.Close(); err != nil {
			f.logger.Debug2("forwarder: UDP conn close error for %v: %v", epID(id), err)
		}
		if err := conn.outConn.Close(); err != nil {
			f.logger.Debug2("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}

		conn.ep.Close()
		delete(f.conns, id)
	}
}

// cleanup periodically removes idle UDP connections
func (f *udpForwarder) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			var idleConns []idleConn

			f.RLock()
			for id, conn := range f.conns {
				if conn.getIdleDuration() > udpTimeout {
					idleConns = append(idleConns, idleConn{id, conn})
				}
			}
			f.RUnlock()

			for _, idle := range idleConns {
				idle.conn.cancel()
				if err := idle.conn.conn.Close(); err != nil {
					f.logger.Debug2("forwarder: UDP conn close error for %v: %v", epID(idle.id), err)
				}
				if err := idle.conn.outConn.Close(); err != nil {
					f.logger.Debug2("forwarder: UDP outConn close error for %v: %v", epID(idle.id), err)
				}

				idle.conn.ep.Close()

				f.Lock()
				delete(f.conns, idle.id)
				f.Unlock()

				f.logger.Trace1("forwarder: cleaned up idle UDP connection %v", epID(idle.id))
			}
		}
	}
}

// handleUDP is called by the UDP forwarder for new packets
func (f *Forwarder) handleUDP(r *udp.ForwarderRequest) bool {
	if f.ctx.Err() != nil {
		f.logger.Trace("forwarder: context done, dropping UDP packet")
		return false
	}

	id := r.ID()

	f.udpForwarder.RLock()
	_, exists := f.udpForwarder.conns[id]
	f.udpForwarder.RUnlock()
	if exists {
		f.logger.Trace1("forwarder: existing UDP connection for %v", epID(id))
		return true
	}

	flowID := uuid.New()

	f.sendUDPEvent(nftypes.TypeStart, flowID, id, 0, 0, 0, 0)
	var success bool
	defer func() {
		if !success {
			f.sendUDPEvent(nftypes.TypeEnd, flowID, id, 0, 0, 0, 0)
		}
	}()

	dstAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)
	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "udp", dstAddr)
	if err != nil {
		f.logger.Debug2("forwarder: UDP dial error for %v: %v", epID(id), err)
		// TODO: Send ICMP error message
		return false
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		f.logger.Debug1("forwarder: failed to create UDP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			f.logger.Debug2("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}
		return false
	}

	inConn := gonet.NewUDPConn(&wq, ep)
	connCtx, connCancel := context.WithCancel(f.ctx)

	pConn := &udpPacketConn{
		conn:    inConn,
		outConn: outConn,
		cancel:  connCancel,
		ep:      ep,
		flowID:  flowID,
	}
	pConn.updateLastSeen()

	f.udpForwarder.Lock()
	// Double-check no connection was created while we were setting up
	if _, exists := f.udpForwarder.conns[id]; exists {
		f.udpForwarder.Unlock()
		pConn.cancel()
		if err := inConn.Close(); err != nil {
			f.logger.Debug2("forwarder: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := outConn.Close(); err != nil {
			f.logger.Debug2("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}
		return true
	}
	f.udpForwarder.conns[id] = pConn
	f.udpForwarder.Unlock()

	success = true
	f.logger.Trace1("forwarder: established UDP connection %v", epID(id))

	go f.proxyUDP(connCtx, pConn, id, ep)
	return true
}

func (f *Forwarder) proxyUDP(ctx context.Context, pConn *udpPacketConn, id stack.TransportEndpointID, ep tcpip.Endpoint) {

	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	go func() {
		<-ctx.Done()

		pConn.cancel()
		if err := pConn.conn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug2("forwarder: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := pConn.outConn.Close(); err != nil && !isClosedError(err) {
			f.logger.Debug2("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}

		ep.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var txBytes, rxBytes int64
	var outboundErr, inboundErr error

	// outbound->inbound: copy from pConn.conn to pConn.outConn
	go func() {
		defer wg.Done()
		txBytes, outboundErr = pConn.copy(ctx, pConn.conn, pConn.outConn, &f.udpForwarder.bufPool, "outbound->inbound")
	}()

	// inbound->outbound: copy from pConn.outConn to pConn.conn
	go func() {
		defer wg.Done()
		rxBytes, inboundErr = pConn.copy(ctx, pConn.outConn, pConn.conn, &f.udpForwarder.bufPool, "inbound->outbound")
	}()

	wg.Wait()

	if outboundErr != nil && !isClosedError(outboundErr) {
		f.logger.Error2("proxyUDP: copy error (outbound→inbound) for %s: %v", epID(id), outboundErr)
	}
	if inboundErr != nil && !isClosedError(inboundErr) {
		f.logger.Error2("proxyUDP: copy error (inbound→outbound) for %s: %v", epID(id), inboundErr)
	}

	var rxPackets, txPackets uint64
	if udpStats, ok := ep.Stats().(*tcpip.TransportEndpointStats); ok {
		// fields are flipped since this is the in conn
		rxPackets = udpStats.PacketsSent.Value()
		txPackets = udpStats.PacketsReceived.Value()
	}

	f.logger.Trace5("forwarder: Removed UDP connection %s [in: %d Pkts/%d B, out: %d Pkts/%d B]", epID(id), rxPackets, rxBytes, txPackets, txBytes)

	f.udpForwarder.Lock()
	delete(f.udpForwarder.conns, id)
	f.udpForwarder.Unlock()

	f.sendUDPEvent(nftypes.TypeEnd, pConn.flowID, id, uint64(rxBytes), uint64(txBytes), rxPackets, txPackets)
}

// sendUDPEvent stores flow events for UDP connections
func (f *Forwarder) sendUDPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, rxBytes, txBytes, rxPackets, txPackets uint64) {
	srcIp := netip.AddrFrom4(id.RemoteAddress.As4())
	dstIp := netip.AddrFrom4(id.LocalAddress.As4())

	fields := nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.UDP,
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

func (c *udpPacketConn) updateLastSeen() {
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *udpPacketConn) getIdleDuration() time.Duration {
	lastSeen := time.Unix(0, c.lastSeen.Load())
	return time.Since(lastSeen)
}

// copy reads from src and writes to dst.
func (c *udpPacketConn) copy(ctx context.Context, dst net.Conn, src net.Conn, bufPool *sync.Pool, direction string) (int64, error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buffer := *bufp
	var totalBytes int64 = 0

	for {
		if ctx.Err() != nil {
			return totalBytes, ctx.Err()
		}

		if err := src.SetDeadline(time.Now().Add(udpTimeout)); err != nil {
			return totalBytes, fmt.Errorf("set read deadline: %w", err)
		}

		n, err := src.Read(buffer)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return totalBytes, fmt.Errorf("read from %s: %w", direction, err)
		}

		nWritten, err := dst.Write(buffer[:n])
		if err != nil {
			return totalBytes, fmt.Errorf("write to %s: %w", direction, err)
		}

		totalBytes += int64(nWritten)
		c.updateLastSeen()
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF)
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
