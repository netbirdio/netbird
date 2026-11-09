// Package sweep cuts network-bound activity when the OS switches networks:
// a sweep closes the registered connections and aborts the in-flight dials, so
// their owners redial immediately instead of waiting for the old sockets to
// time out.
//
// A nil *Sweeper disables everything: all methods are nil-safe no-ops.
package sweep

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/netevents/netstate"
)

// DefaultSweepDelay absorbs network flapping while the OS settles on a
// default network before the stale registrations are cut.
const DefaultSweepDelay = 500 * time.Millisecond

const recentMarkWindow = 3 * time.Second

// Config customizes a Sweeper. The zero value applies the defaults.
type Config struct {
	// SweepDelay overrides DefaultSweepDelay when positive.
	SweepDelay time.Duration
}

// ErrSwept reports that a dial finished after a network change swept its
// registration. The connection is already closed; the caller must treat it
// as a failed dial and redial on the new network.
var ErrSwept = errors.New("sweep: connection swept by network change")

// sweepID identifies one registration in a sweeper. Connections and dials
// draw from the same counter, so an id is unique across both registries.
type sweepID uint64

type connEntry struct {
	conn net.Conn
	gen  uint64
}

// Dial tracks one dial from start to connection registration. It hands the
// dialed connection to the sweeper atomically, so a sweep can never fall
// between the dial finishing and the connection being registered.
type Dial struct {
	sweeper *Sweeper
	ctx     context.Context
	cancel  context.CancelFunc
	id      sweepID
	done    bool // set by a sweep, WrapConn or Release; guarded by sweeper.mu
	gen     uint64
}

// Ctx returns the dial's context. A sweep cancels it, so a dial started on the
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

// Sweeper registers live connections and in-flight dials so the
// network-change sweep can cut everything registered before the change.
type Sweeper struct {
	mu         sync.Mutex
	conns      map[sweepID]connEntry
	dials      map[sweepID]*Dial
	nextID     sweepID
	gen        uint64
	timer      *time.Timer
	sweepDelay time.Duration
	lastMark   time.Time
}

// New creates an empty sweeper with the default configuration.
func New() *Sweeper {
	return NewWithConfig(Config{})
}

// NewWithConfig creates an empty sweeper customized by cfg.
func NewWithConfig(cfg Config) *Sweeper {
	delay := cfg.SweepDelay
	if delay <= 0 {
		delay = DefaultSweepDelay
	}
	return &Sweeper{
		conns:      make(map[sweepID]connEntry),
		dials:      make(map[sweepID]*Dial),
		sweepDelay: delay,
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
	d.gen = s.gen
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
	// The conn inherits the dial's generation: the socket was bound to the
	// network that was default when the dial started, not when it finished.
	s.conns[id] = connEntry{conn: conn, gen: d.gen}
	s.mu.Unlock()

	return &sweptConn{Conn: conn, sweeper: s, id: id}, nil
}

// MarkNetworkChange records that the OS switched networks: everything
// registered so far becomes stale, and a sweep is (re)scheduled after the
// configured delay to cut whatever is still stale by then. Owners that
// redialed in the meantime hold fresh-generation registrations and survive,
// so no cancellation is needed around the sweep.
func (s *Sweeper) MarkNetworkChange() {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.gen++
	cutoff := s.gen
	s.lastMark = time.Now()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.sweepDelay, func() {
		n := s.sweep(cutoff)
		log.Infof("network change sweep: closed %d stale connections", n)
	})
	s.mu.Unlock()
}

// QuickRetryBackoff wraps bo so that after each Reset the first retry comes
// quickly when the disconnect followed a recent network change and the
// network is online. Any other failure keeps bo's spread, so the clients of
// a restarted server still scatter their reconnects. A nil sweeper returns
// bo unchanged.
func (s *Sweeper) QuickRetryBackoff(ctx context.Context, bo backoff.BackOff, netState *netstate.State) backoff.BackOff {
	if s == nil {
		return bo
	}
	return backoff.WithContext(newQuickRetryBackoff(bo, s, netState), ctx)
}

func (s *Sweeper) markedRecently() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastMark.IsZero() && time.Since(s.lastMark) < recentMarkWindow
}

// sweep closes the registered connections and aborts the in-flight dials
// older than cutoff, and returns how many connections it closed. A dial
// whose connection was not yet handed to WrapConn is marked, so the late
// WrapConn closes it instead of registering it.
func (s *Sweeper) sweep(cutoff uint64) int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	var conns []net.Conn
	for id, e := range s.conns {
		if e.gen < cutoff {
			delete(s.conns, id)
			conns = append(conns, e.conn)
		}
	}
	var dials []*Dial
	for id, d := range s.dials {
		if d.gen < cutoff {
			d.done = true
			delete(s.dials, id)
			dials = append(dials, d)
		}
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
