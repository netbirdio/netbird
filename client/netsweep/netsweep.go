// Package netsweep cuts network-bound activity when the OS switches networks:
// a sweep closes the registered connections and aborts the in-flight dials, so
// their owners redial immediately instead of waiting for the old sockets to
// time out.
//
// A nil *Sweeper disables everything: all methods are nil-safe no-ops.
package netsweep

import (
	"context"
	"errors"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ErrSwept reports that a dial finished after a network change swept its
// registration. The connection is already closed; the caller must treat it
// as a failed dial and redial on the new network.
var ErrSwept = errors.New("netsweep: connection swept by network change")

// sweepID identifies one registration in a sweeper. Connections and dials
// draw from the same counter, so an id is unique across both registries.
type sweepID uint64

// Dial tracks one dial from start to connection registration. It hands the
// dialed connection to the sweeper atomically, so a sweep can never fall
// between the dial finishing and the connection being registered.
type Dial struct {
	sweeper *Sweeper
	ctx     context.Context
	cancel  context.CancelFunc
	id      sweepID
	done    bool // set by Sweep, WrapConn or Release; guarded by sweeper.mu
}

// Ctx returns the dial's context. Sweep cancels it, so a dial started on the
// old network aborts instead of waiting out its handshake timeout.
func (d *Dial) Ctx() context.Context {
	return d.ctx
}

// Release ends the dial's registration and cancels its context. It is
// idempotent and safe after WrapConn, so callers can defer it.
func (d *Dial) Release() {
	s := d.sweeper
	if s == nil {
		return
	}

	s.mu.Lock()
	d.done = true
	delete(s.dials, d.id)
	s.mu.Unlock()

	d.cancel()
}

// sweptConn deregisters itself from the sweeper when closed.
type sweptConn struct {
	net.Conn
	sweeper *Sweeper
	id      sweepID
}

func (c *sweptConn) Close() error {
	c.sweeper.deregister(c.id)
	return c.Conn.Close()
}

// Sweeper registers live connections and in-flight dials so Sweep can cut
// everything that started before the network changed.
type Sweeper struct {
	mu     sync.Mutex
	conns  map[sweepID]net.Conn
	dials  map[sweepID]*Dial
	nextID sweepID
}

// New creates an empty sweeper.
func New() *Sweeper {
	return &Sweeper{
		conns: make(map[sweepID]net.Conn),
		dials: make(map[sweepID]*Dial),
	}
}

// StartDial registers an in-flight dial. Dial with Ctx, hand the result to
// WrapConn, and Release the dial when the attempt is over, typically deferred.
func (s *Sweeper) StartDial(ctx context.Context) *Dial {
	if s == nil {
		return &Dial{ctx: ctx}
	}

	ctx, cancel := context.WithCancel(ctx)
	d := &Dial{sweeper: s, ctx: ctx, cancel: cancel}

	s.mu.Lock()
	d.id = s.nextID
	s.nextID++
	s.dials[d.id] = d
	s.mu.Unlock()

	return d
}

// WrapConn hands conn over to the sweeper. If a sweep ran since StartDial,
// the connection belongs to the old network: it is closed and ErrSwept is
// returned. Otherwise conn is registered against the next sweep and returned
// wrapped, deregistering itself on Close. Call it once, before Release.
func (d *Dial) WrapConn(conn net.Conn) (net.Conn, error) {
	s := d.sweeper
	if s == nil {
		return conn, nil
	}

	s.mu.Lock()
	if d.done {
		s.mu.Unlock()
		if err := conn.Close(); err != nil {
			log.Debugf("swept dial close error: %v", err)
		}
		return nil, ErrSwept
	}
	d.done = true
	delete(s.dials, d.id)
	id := s.nextID
	s.nextID++
	s.conns[id] = conn
	s.mu.Unlock()

	return &sweptConn{Conn: conn, sweeper: s, id: id}, nil
}

// Sweep closes every registered connection, aborts every in-flight dial, and
// returns how many connections it closed. A dial whose connection was not
// yet handed to WrapConn is marked, so the late WrapConn closes it instead
// of registering it.
func (s *Sweeper) Sweep() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	conns := s.conns
	dials := s.dials
	s.conns = make(map[sweepID]net.Conn)
	s.dials = make(map[sweepID]*Dial)
	for _, d := range dials {
		d.done = true
	}
	s.mu.Unlock()

	if len(dials) > 0 {
		log.Debugf("aborting %d in-flight dials", len(dials))
		for _, d := range dials {
			d.cancel()
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

func (s *Sweeper) deregister(id sweepID) {
	s.mu.Lock()
	delete(s.conns, id)
	s.mu.Unlock()
}
