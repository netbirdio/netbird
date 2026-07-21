package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The FallbackOpener race is driven by a single goroutine (Run's select loop)
// with worker goroutines that communicate only through the buffered results
// channel and the two cancel contexts. These tests exercise that state machine
// in isolation via an injected openFn, so no relay server or network is needed.
// Timing is scaled down through the fallbackDelay/totalTimeout fields.

// raceFakeConn tracks whether Close was called. Only Close is exercised by the
// race logic (drainLoser closes losers; Run returns the winner untouched).
type raceFakeConn struct {
	net.Conn
	label  string
	closed atomic.Bool
}

func (c *raceFakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

// raceAttemptScript describes how a single scripted attempt behaves.
type raceAttemptScript struct {
	delay time.Duration
	conn  *raceFakeConn // non-nil => the attempt succeeds and returns this conn
	err   error         // returned when conn is nil
	// ignoreCtx makes the attempt complete after delay even if its context is
	// cancelled. It models an OpenConn that produced a real connection right as
	// the race cancelled it - exactly the case drainLoser must clean up.
	ignoreCtx bool
}

// fakeOpener replaces FallbackOpener.open. Scripts are keyed by the foreign
// flag, so which script is "preferred" depends on the preferForeign argument
// passed to Run.
type fakeOpener struct {
	mu      sync.Mutex
	scripts map[bool]raceAttemptScript
	calls   []bool // foreign flag of each open() invocation, in order
}

func (f *fakeOpener) open(ctx context.Context, _ string, _ RelayServer, foreign bool) raceAttempt {
	f.mu.Lock()
	f.calls = append(f.calls, foreign)
	s, ok := f.scripts[foreign]
	f.mu.Unlock()
	if !ok {
		return raceAttempt{err: fmt.Errorf("no script for foreign=%v", foreign)}
	}

	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		if s.ignoreCtx {
			<-timer.C
		} else {
			select {
			case <-timer.C:
			case <-ctx.Done():
				return raceAttempt{err: ctx.Err()}
			}
		}
	}

	if s.conn != nil {
		return raceAttempt{conn: s.conn}
	}
	return raceAttempt{err: s.err}
}

func (f *fakeOpener) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeOpener) firstCallForeign(t *testing.T) bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.calls, "expected at least one open attempt")
	return f.calls[0]
}

func newTestOpener(f *fakeOpener, fallbackDelay, totalTimeout time.Duration) *FallbackOpener {
	o := NewFallbackOpener(nil, nil)
	o.openFn = f.open
	o.fallbackDelay = fallbackDelay
	o.totalTimeout = totalTimeout
	return o
}

const (
	// controller prefers the home relay, i.e. preferForeign == false.
	preferHome    = false
	preferForeign = true
)

var errAttempt = errors.New("attempt failed")

// The preferred attempt wins before the fallback timer fires, so the other
// attempt is never started.
func TestFallbackOpener_PreferredWinsImmediately(t *testing.T) {
	homeConn := &raceFakeConn{label: "home"}
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {conn: homeConn},                            // preferred (home): instant success
		true:  {delay: 5 * time.Second, conn: foreignConn}, // would never finish in time
	}}
	o := newTestOpener(f, 40*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.NoError(t, err)
	require.Same(t, homeConn, conn)
	assert.Equal(t, 1, f.callCount(), "other attempt must not start when preferred wins first")
	assert.False(t, f.firstCallForeign(t), "home must be tried first when preferring home")
	assert.False(t, foreignConn.closed.Load())
}

// preferForeign flips which relay is tried first.
func TestFallbackOpener_PreferForeignRoutesForeignFirst(t *testing.T) {
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		true:  {conn: foreignConn}, // preferred (foreign): instant success
		false: {delay: 5 * time.Second, conn: &raceFakeConn{}},
	}}
	o := newTestOpener(f, 40*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferForeign)

	require.NoError(t, err)
	require.Same(t, foreignConn, conn)
	assert.Equal(t, 1, f.callCount())
	assert.True(t, f.firstCallForeign(t), "foreign must be tried first when preferring foreign")
}

// ErrConnAlreadyExists counts as success: Run returns it and does not start the
// other attempt.
func TestFallbackOpener_ErrConnAlreadyExistsIsSuccess(t *testing.T) {
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {err: ErrConnAlreadyExists},
		true:  {delay: 5 * time.Second, conn: &raceFakeConn{}},
	}}
	o := newTestOpener(f, 40*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.ErrorIs(t, err, ErrConnAlreadyExists)
	assert.Nil(t, conn)
	assert.Equal(t, 1, f.callCount(), "other attempt must not start on ErrConnAlreadyExists")
}

// A preferred failure starts the other attempt immediately, without waiting for
// the fallback timer.
func TestFallbackOpener_PreferredFailsStartsOtherBeforeTimer(t *testing.T) {
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {err: errAttempt}, // preferred fails instantly
		true:  {delay: 5 * time.Millisecond, conn: foreignConn},
	}}
	fallbackDelay := 500 * time.Millisecond
	o := newTestOpener(f, fallbackDelay, 2*time.Second)

	start := time.Now()
	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Same(t, foreignConn, conn)
	assert.Equal(t, 2, f.callCount())
	assert.Less(t, elapsed, fallbackDelay/2, "fallback must not wait for the timer after a preferred failure")
}

// When the preferred attempt is slow, the fallback timer starts the other
// attempt and its success wins.
func TestFallbackOpener_TimerStartsOtherWhenPreferredSlow(t *testing.T) {
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {delay: 5 * time.Second}, // preferred hangs until cancelled
		true:  {delay: 5 * time.Millisecond, conn: foreignConn},
	}}
	fallbackDelay := 40 * time.Millisecond
	o := newTestOpener(f, fallbackDelay, 2*time.Second)

	start := time.Now()
	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Same(t, foreignConn, conn)
	assert.Equal(t, 2, f.callCount())
	assert.GreaterOrEqual(t, elapsed, fallbackDelay, "other must not start before the fallback timer fires")
}

// Both attempts fail: Run returns the last error and tries both relays.
func TestFallbackOpener_BothFail(t *testing.T) {
	errOther := errors.New("other failed")
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {err: errAttempt},
		true:  {err: errOther},
	}}
	o := newTestOpener(f, 40*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, errOther, "the most recent error should be surfaced")
	assert.Equal(t, 2, f.callCount())
}

// When both attempts succeed, drainLoser must close the losing connection so it
// is not leaked. Here the preferred attempt wins and the foreign loser - which
// produced a real conn despite being cancelled - is closed.
func TestFallbackOpener_DoubleSuccessClosesLoser(t *testing.T) {
	homeConn := &raceFakeConn{label: "home"}
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {delay: 30 * time.Millisecond, conn: homeConn},                     // preferred wins
		true:  {delay: 80 * time.Millisecond, conn: foreignConn, ignoreCtx: true}, // loser yields a conn after cancel
	}}
	o := newTestOpener(f, 15*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.NoError(t, err)
	require.Same(t, homeConn, conn)
	assert.Equal(t, 2, f.callCount())
	assert.False(t, homeConn.closed.Load(), "the winning connection must not be closed")
	require.Eventually(t, foreignConn.closed.Load, time.Second, 5*time.Millisecond,
		"the losing connection must be closed by drainLoser")
}

// Winner selection is purely by result arrival order, not by preference: when
// the non-preferred attempt returns first it wins even though home was
// preferred. This is the mechanism behind the split-relay concern - two peers
// racing independently have no shared tie-break, so under adversarial timing
// they can settle on different relays. Documented here as current behavior.
func TestFallbackOpener_FasterOtherWinsDespitePreference(t *testing.T) {
	homeConn := &raceFakeConn{label: "home"}
	foreignConn := &raceFakeConn{label: "foreign"}
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {delay: 60 * time.Millisecond, conn: homeConn, ignoreCtx: true}, // preferred but slower
		true:  {delay: 5 * time.Millisecond, conn: foreignConn},                // other is faster
	}}
	o := newTestOpener(f, 15*time.Millisecond, 2*time.Second)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.NoError(t, err)
	require.Same(t, foreignConn, conn, "the first successful attempt wins regardless of preference")
	require.Eventually(t, homeConn.closed.Load, time.Second, 5*time.Millisecond,
		"the slower preferred attempt becomes the loser and is closed")
}

// The whole race is bounded by totalTimeout. With no attempt succeeding or
// failing, Run returns the deadline error.
func TestFallbackOpener_TotalTimeout(t *testing.T) {
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {delay: 5 * time.Second},
		true:  {delay: 5 * time.Second},
	}}
	o := newTestOpener(f, 20*time.Millisecond, 80*time.Millisecond)

	conn, err := o.Run(context.Background(), "peer", RelayServer{Addr: "srv"}, preferHome)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// Cancelling the caller's context aborts the race promptly with the cancel
// error, even before the fallback timer would fire.
func TestFallbackOpener_ParentContextCanceled(t *testing.T) {
	f := &fakeOpener{scripts: map[bool]raceAttemptScript{
		false: {delay: 5 * time.Second},
		true:  {delay: 5 * time.Second},
	}}
	// fallbackDelay large so the timer never fires; only the parent cancel ends the race.
	o := newTestOpener(f, 5*time.Second, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	conn, err := o.Run(ctx, "peer", RelayServer{Addr: "srv"}, preferHome)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second, "must return shortly after the parent context is cancelled")
	assert.Equal(t, 1, f.callCount(), "the other attempt must not start")
}

// rendezvous models the relay-level requirement that a relayed connection is
// established only once BOTH peers subscribe to the same relay server. arrive
// records a peer's presence on a relay and returns a channel that closes when
// the second peer arrives, so an attempt can only complete after a real
// rendezvous - the same coupling the production code depends on.
type rendezvous struct {
	mu       sync.Mutex
	arrivals map[string]int
	gates    map[string]chan struct{}
}

func newRendezvous() *rendezvous {
	return &rendezvous{arrivals: map[string]int{}, gates: map[string]chan struct{}{}}
}

func (r *rendezvous) arrive(relay string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.gates[relay]
	if !ok {
		g = make(chan struct{})
		r.gates[relay] = g
	}
	r.arrivals[relay]++
	if r.arrivals[relay] == 2 {
		close(g)
	}
	return g
}

// splitPeer is one peer's view of the two relays. relayFor maps the foreign
// flag to a relay name; postDelay is how long after the rendezvous that peer's
// OpenConn takes to return (its per-relay subscribe latency). Different values
// per peer model the asymmetric timing that triggers finding #1.
type splitPeer struct {
	rv        *rendezvous
	relayFor  map[bool]string
	postDelay map[string]time.Duration
}

func (p *splitPeer) open(ctx context.Context, _ string, _ RelayServer, foreign bool) raceAttempt {
	relay := p.relayFor[foreign]

	select {
	case <-p.rv.arrive(relay):
	case <-ctx.Done():
		return raceAttempt{err: ctx.Err()}
	}

	timer := time.NewTimer(p.postDelay[relay])
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return raceAttempt{err: ctx.Err()}
	}
	return raceAttempt{conn: &raceFakeConn{label: relay}}
}

// TestFallbackOpener_SplitRelaySelection reproduces finding #1: the two peers
// run FallbackOpener.Run independently with no shared tie-break, so the winner
// is chosen purely by local result-arrival order. Under an adversarial - but
// self-consistent - timing profile they settle on DIFFERENT relays.
//
// Both peers prefer relayA (the controller's home). The split needs each peer's
// preferred relayA to be slow enough that both start their fallback (so both
// relays actually rendezvous), and then each peer's fast path to be a different
// relay:
//   - peerA: relayA slow (abandoned), relayB fast  -> peerA wins relayB
//   - peerB: relayA fast (wins),      relayB slow  -> peerB wins relayA
//
// Each winner then cancels its attempt on the relay the OTHER peer actually
// kept, leaving two half-open relayed connections that were both reported as
// successful. When a deterministic cross-peer tie-break is added to fix this,
// invert the assertion below to require convergence.
func TestFallbackOpener_SplitRelaySelection(t *testing.T) {
	const (
		relayA = "relayA" // controller's home relay; both peers prefer it
		relayB = "relayB" // non-controller's home relay
	)
	rv := newRendezvous()

	peerA := &splitPeer{
		rv:       rv,
		relayFor: map[bool]string{false: relayA, true: relayB}, // home=relayA
		postDelay: map[string]time.Duration{
			relayA: 500 * time.Millisecond, // preferred but slow -> abandoned
			relayB: 10 * time.Millisecond,  // fallback is fast -> peerA wins relayB
		},
	}
	peerB := &splitPeer{
		rv:       rv,
		relayFor: map[bool]string{false: relayB, true: relayA}, // home=relayB
		postDelay: map[string]time.Duration{
			relayA: 80 * time.Millisecond,  // preferred, wins - but only after starting fallback
			relayB: 500 * time.Millisecond, // fallback (home) is slow -> abandoned
		},
	}

	fallbackDelay := 30 * time.Millisecond
	newPeerOpener := func(p *splitPeer) *FallbackOpener {
		o := NewFallbackOpener(nil, nil)
		o.openFn = p.open
		o.fallbackDelay = fallbackDelay
		o.totalTimeout = 5 * time.Second
		return o
	}
	oA := newPeerOpener(peerA)
	oB := newPeerOpener(peerB)

	type result struct {
		conn net.Conn
		err  error
	}
	var ra, rb result
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ra.conn, ra.err = oA.Run(context.Background(), "peerB", RelayServer{Addr: relayB}, preferHome)
	}()
	go func() {
		defer wg.Done()
		rb.conn, rb.err = oB.Run(context.Background(), "peerA", RelayServer{Addr: relayA}, preferForeign)
	}()
	wg.Wait()

	require.NoError(t, ra.err)
	require.NoError(t, rb.err)
	aRelay := ra.conn.(*raceFakeConn).label
	bRelay := rb.conn.(*raceFakeConn).label
	t.Logf("peerA settled on %s, peerB settled on %s", aRelay, bRelay)

	assert.Equal(t, aRelay, bRelay,
		"peers selected different relays with no cross-peer tie-break")
	assert.Equal(t, relayB, aRelay, "peerA abandoned its slow preferred relay and won the fallback")
	assert.Equal(t, relayA, bRelay, "peerB won its preferred relay after starting the fallback")
}
