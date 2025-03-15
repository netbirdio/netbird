package forwarder

import (
	"context"
	"errors"
	"fmt"
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

func newUDPForwarder(mtu int, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *udpForwarder {
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
			f.logger.Debug("forwarder: UDP conn close error for %v: %v", epID(id), err)
		}
		if err := conn.outConn.Close(); err != nil {
			f.logger.Debug("forwarder: UDP outConn close error for %v: %v", epID(id), err)
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
					f.logger.Debug("forwarder: UDP conn close error for %v: %v", epID(idle.id), err)
				}
				if err := idle.conn.outConn.Close(); err != nil {
					f.logger.Debug("forwarder: UDP outConn close error for %v: %v", epID(idle.id), err)
				}

				idle.conn.ep.Close()

				f.Lock()
				delete(f.conns, idle.id)
				f.Unlock()

				f.logger.Trace("forwarder: cleaned up idle UDP connection %v", epID(idle.id))
			}
		}
	}
}

// handleUDP is called by the UDP forwarder for new packets
func (f *Forwarder) handleUDP(r *udp.ForwarderRequest) {
	if f.ctx.Err() != nil {
		f.logger.Trace("forwarder: context done, dropping UDP packet")
		return
	}

	id := r.ID()

	f.udpForwarder.RLock()
	_, exists := f.udpForwarder.conns[id]
	f.udpForwarder.RUnlock()
	if exists {
		f.logger.Trace("forwarder: existing UDP connection for %v", epID(id))
		return
	}

	flowID := uuid.New()

	f.sendUDPEvent(nftypes.TypeStart, flowID, id, nil)
	var success bool
	defer func() {
		if !success {
			f.sendUDPEvent(nftypes.TypeEnd, flowID, id, nil)
		}
	}()

	dstAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)
	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "udp", dstAddr)
	if err != nil {
		f.logger.Debug("forwarder: UDP dial error for %v: %v", epID(id), err)
		// TODO: Send ICMP error message
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		f.logger.Debug("forwarder: failed to create UDP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			f.logger.Debug("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}
		return
	}

	inConn := gonet.NewUDPConn(f.stack, &wq, ep)
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
			f.logger.Debug("forwarder: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := outConn.Close(); err != nil {
			f.logger.Debug("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}

		return
	}
	f.udpForwarder.conns[id] = pConn
	f.udpForwarder.Unlock()

	success = true
	f.logger.Trace("forwarder: established UDP connection %v", epID(id))

	go f.proxyUDP(connCtx, pConn, id, ep)
}

func (f *Forwarder) proxyUDP(ctx context.Context, pConn *udpPacketConn, id stack.TransportEndpointID, ep tcpip.Endpoint) {
	defer func() {
		pConn.cancel()
		if err := pConn.conn.Close(); err != nil {
			f.logger.Debug("forwarder: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := pConn.outConn.Close(); err != nil {
			f.logger.Debug("forwarder: UDP outConn close error for %v: %v", epID(id), err)
		}

		ep.Close()

		f.udpForwarder.Lock()
		delete(f.udpForwarder.conns, id)
		f.udpForwarder.Unlock()

		f.sendUDPEvent(nftypes.TypeEnd, pConn.flowID, id, ep)
	}()

	errChan := make(chan error, 2)

	go func() {
		errChan <- pConn.copy(ctx, pConn.conn, pConn.outConn, &f.udpForwarder.bufPool, "outbound->inbound")
	}()

	go func() {
		errChan <- pConn.copy(ctx, pConn.outConn, pConn.conn, &f.udpForwarder.bufPool, "inbound->outbound")
	}()

	select {
	case <-ctx.Done():
		f.logger.Trace("forwarder: tearing down UDP connection %v due to context done", epID(id))
		return
	case err := <-errChan:
		if err != nil && !isClosedError(err) {
			f.logger.Error("proxyUDP: copy error: %v", err)
		}
		f.logger.Trace("forwarder: tearing down UDP connection %v", epID(id))
		return
	}
}

// sendUDPEvent stores flow events for UDP connections
func (f *Forwarder) sendUDPEvent(typ nftypes.Type, flowID uuid.UUID, id stack.TransportEndpointID, ep tcpip.Endpoint) {
	fields := nftypes.EventFields{
		FlowID:    flowID,
		Type:      typ,
		Direction: nftypes.Ingress,
		Protocol:  nftypes.UDP,
		// TODO: handle ipv6
		SourceIP:   netip.AddrFrom4(id.RemoteAddress.As4()),
		DestIP:     netip.AddrFrom4(id.LocalAddress.As4()),
		SourcePort: id.RemotePort,
		DestPort:   id.LocalPort,
	}

	if ep != nil {
		if tcpStats, ok := ep.Stats().(*tcpip.TransportEndpointStats); ok {
			// fields are flipped since this is the in conn
			// TODO: get bytes
			fields.RxPackets = tcpStats.PacketsSent.Value()
			fields.TxPackets = tcpStats.PacketsReceived.Value()
		}
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

func (c *udpPacketConn) copy(ctx context.Context, dst net.Conn, src net.Conn, bufPool *sync.Pool, direction string) error {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buffer := *bufp

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := src.SetDeadline(time.Now().Add(udpTimeout)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}

		n, err := src.Read(buffer)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return fmt.Errorf("read from %s: %w", direction, err)
		}

		_, err = dst.Write(buffer[:n])
		if err != nil {
			return fmt.Errorf("write to %s: %w", direction, err)
		}

		c.updateLastSeen()
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
