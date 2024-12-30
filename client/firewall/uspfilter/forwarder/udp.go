package forwarder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpTimeout    = 60 * time.Second
	maxPacketSize = 65535
)

type udpPacketConn struct {
	conn     *gonet.UDPConn
	outConn  net.Conn
	lastTime time.Time
	cancel   context.CancelFunc
}

type udpForwarder struct {
	sync.RWMutex
	conns   map[stack.TransportEndpointID]*udpPacketConn
	bufPool sync.Pool
	ctx     context.Context
	cancel  context.CancelFunc
}

func newUDPForwarder() *udpForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	f := &udpForwarder{
		conns:  make(map[stack.TransportEndpointID]*udpPacketConn),
		ctx:    ctx,
		cancel: cancel,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, maxPacketSize)
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
			log.Errorf("forwarder: UDP conn close error for %v: %v", id, err)
		}
		if err := conn.outConn.Close(); err != nil {
			log.Errorf("forwarder: UDP outConn close error for %v: %v", id, err)
		}
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
			f.Lock()
			now := time.Now()
			for id, conn := range f.conns {
				if now.Sub(conn.lastTime) > udpTimeout {
					conn.cancel()
					if err := conn.conn.Close(); err != nil {
						log.Errorf("forwarder: UDP conn close error for %v: %v", id, err)
					}
					if err := conn.outConn.Close(); err != nil {
						log.Errorf("forwarder: UDP outConn close error for %v: %v", id, err)
					}
					delete(f.conns, id)
					log.Debugf("forwarder: cleaned up idle UDP connection %v", id)
				}
			}
			f.Unlock()
		}
	}
}

// handleUDP is called by the UDP forwarder for new packets
func (f *Forwarder) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	if f.ctx.Err() != nil {
		log.Debug("forwarder: context done, dropping UDP packet")
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Errorf("forwarder: failed to create UDP endpoint: %v", err)
		return
	}

	inConn := gonet.NewUDPConn(f.stack, &wq, ep)

	// Try to get existing connection or create a new one
	f.udpForwarder.Lock()
	defer f.udpForwarder.Unlock()

	pConn, exists := f.udpForwarder.conns[id]
	if !exists {
		outConn, err := (&net.Dialer{}).DialContext(f.ctx, "udp", dstAddr)
		if err != nil {
			if err := inConn.Close(); err != nil {
				log.Errorf("forwarder: UDP inConn close error for %v: %v", id, err)
			}
			log.Errorf("forwarder: UDP dial error for %v: %v", id, err)
			return
		}

		connCtx, connCancel := context.WithCancel(f.ctx)
		pConn = &udpPacketConn{
			conn:     inConn,
			outConn:  outConn,
			lastTime: time.Now(),
			cancel:   connCancel,
		}
		f.udpForwarder.conns[id] = pConn

		go f.proxyUDP(connCtx, pConn, id)
	}
}

func (f *Forwarder) proxyUDP(ctx context.Context, pConn *udpPacketConn, id stack.TransportEndpointID) {
	defer func() {
		pConn.cancel()
		if err := pConn.conn.Close(); err != nil {
			log.Errorf("forwarder: UDP inConn close error for %v: %v", id, err)
		}
		if err := pConn.outConn.Close(); err != nil {
			log.Errorf("forwarder: UDP outConn close error for %v: %v", id, err)
		}

		f.udpForwarder.Lock()
		delete(f.udpForwarder.conns, id)
		f.udpForwarder.Unlock()
	}()

	errChan := make(chan error, 2)

	go func() {
		errChan <- f.copyUDP(ctx, pConn.conn, pConn.outConn, id, "outbound->inbound")
	}()

	go func() {
		errChan <- f.copyUDP(ctx, pConn.outConn, pConn.conn, id, "inbound->outbound")
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-errChan:
		if err != nil && !isClosedError(err) {
			log.Errorf("forwader: UDP proxy error for %v: %v", id, err)
		}
		return
	}
}

func (f *Forwarder) copyUDP(ctx context.Context, dst net.Conn, src net.Conn, id stack.TransportEndpointID, direction string) error {
	bufp := f.udpForwarder.bufPool.Get().(*[]byte)
	defer f.udpForwarder.bufPool.Put(bufp)
	buffer := *bufp

	if err := src.SetReadDeadline(time.Now().Add(udpTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	if err := src.SetWriteDeadline(time.Now().Add(udpTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
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

			f.udpForwarder.Lock()
			if conn, ok := f.udpForwarder.conns[id]; ok {
				conn.lastTime = time.Now()
			}
			f.udpForwarder.Unlock()
		}
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
