// Package netsweep cuts network-bound activity when the OS switches networks:
// a sweep closes the registered connections and aborts the in-flight dials, so
// their owners redial immediately instead of waiting for the old sockets to
// time out.
//
// A nil *Sweeper disables everything: all methods are nil-safe no-ops.
package netsweep

import (
	"context"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// sweptConn deregisters itself from the sweeper when closed.
type sweptConn struct {
	net.Conn
	sweeper *Sweeper
	id      uint64
}

func (c *sweptConn) Close() error {
	c.sweeper.deregister(c.id)
	return c.Conn.Close()
}

// Sweeper registers live connections and in-flight dials so Sweep can cut
// everything that started before the network changed.
type Sweeper struct {
	mu     sync.Mutex
	conns  map[uint64]net.Conn
	dials  map[uint64]context.CancelFunc
	nextID uint64
}

// New creates an empty sweeper.
func New() *Sweeper {
	return &Sweeper{
		conns: make(map[uint64]net.Conn),
		dials: make(map[uint64]context.CancelFunc),
	}
}

// WrapConn registers conn and returns a wrapper that deregisters it on Close.
func (s *Sweeper) WrapConn(conn net.Conn) net.Conn {
	if s == nil {
		return conn
	}

	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.conns[id] = conn
	s.mu.Unlock()

	return &sweptConn{Conn: conn, sweeper: s, id: id}
}

// WrapDialContext derives a context that Sweep cancels. The returned release
// must be called when the dial finishes, typically deferred.
func (s *Sweeper) WrapDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s == nil {
		return ctx, func() {}
	}

	ctx, cancel := context.WithCancel(ctx)

	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.dials[id] = cancel
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		delete(s.dials, id)
		s.mu.Unlock()
		cancel()
	}
	return ctx, release
}

// Sweep closes every registered connection, aborts every in-flight dial, and
// returns how many connections it closed.
func (s *Sweeper) Sweep() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	conns := s.conns
	dials := s.dials
	s.conns = make(map[uint64]net.Conn)
	s.dials = make(map[uint64]context.CancelFunc)
	s.mu.Unlock()

	if len(dials) > 0 {
		log.Debugf("aborting %d in-flight dials", len(dials))
		for _, cancel := range dials {
			cancel()
		}
	}

	for _, conn := range conns {
		log.Debugf("sweeping connection %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			log.Debugf("swept connection close error: %v", err)
		}
	}
	return len(conns)
}

func (s *Sweeper) deregister(id uint64) {
	s.mu.Lock()
	delete(s.conns, id)
	s.mu.Unlock()
}
