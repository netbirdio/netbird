package netsweep

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSweepClosesRegisteredConns(t *testing.T) {
	sweeper := New()

	c1 := wrap(t, sweeper, connPair(t))
	c2 := wrap(t, sweeper, connPair(t))

	assert.Equal(t, 2, sweeper.sweepAll(), "both live connections should be closed")

	// The wrappers must report closed now.
	buf := make([]byte, 1)
	_, err := c1.Read(buf)
	assert.Error(t, err, "first connection should be unusable after the sweep")
	_, err = c2.Read(buf)
	assert.Error(t, err, "second connection should be unusable after the sweep")

	assert.Equal(t, 0, sweeper.sweepAll(), "second sweep should find nothing")
}

func TestCloseDeregisters(t *testing.T) {
	sweeper := New()

	conn := wrap(t, sweeper, connPair(t))
	require.NoError(t, conn.Close())

	assert.Equal(t, 0, sweeper.sweepAll(), "closed connection must leave the registry")
}

func TestCloseIsIdempotent(t *testing.T) {
	sweeper := New()

	conn := wrap(t, sweeper, connPair(t))
	require.NoError(t, conn.Close())
	assert.Error(t, conn.Close(), "double close surfaces the underlying error but must not panic")
}

func TestSweepOnlyAffectsOlderConns(t *testing.T) {
	sweeper := New()

	_ = wrap(t, sweeper, connPair(t))
	assert.Equal(t, 1, sweeper.sweepAll())

	// A connection dialed after the sweep must survive until the next one.
	_ = wrap(t, sweeper, connPair(t))
	assert.Equal(t, 1, sweeper.sweepAll(), "post-sweep connection belongs to the next sweep")
}

func TestSweepAbortsInFlightDials(t *testing.T) {
	sweeper := New()

	dial := sweeper.StartDial(context.Background())
	defer dial.Release()

	sweeper.sweepAll()

	assert.ErrorIs(t, dial.Ctx().Err(), context.Canceled, "sweep must cancel the in-flight dial context")
}

func TestReleasedDialIsNotAborted(t *testing.T) {
	sweeper := New()

	// Simulate a dial that finished before the sweep.
	released := sweeper.StartDial(context.Background())
	released.Release()

	// A dial still in flight during the sweep.
	pending := sweeper.StartDial(context.Background())
	defer pending.Release()

	sweeper.sweepAll()
	assert.ErrorIs(t, pending.Ctx().Err(), context.Canceled, "pending dial must be aborted")
}

func TestSweepBetweenDialAndHandoffClosesConn(t *testing.T) {
	sweeper := New()

	dial := sweeper.StartDial(context.Background())
	defer dial.Release()

	// The dial succeeds on the old network, then the sweep lands before the
	// connection is handed over.
	conn := connPair(t)
	assert.Equal(t, 0, sweeper.sweepAll(), "the connection is not registered yet")

	wrapped, err := dial.WrapConn(conn)
	require.ErrorIs(t, err, ErrSwept)
	require.Nil(t, wrapped)

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	assert.Error(t, err, "the old-network connection must be closed, not leaked")

	assert.Equal(t, 0, sweeper.sweepAll(), "nothing may leak into the next sweep")
}

func TestMarkNetworkChangeSparesFreshConns(t *testing.T) {
	sweeper := NewWithConfig(Config{SweepDelay: 10 * time.Millisecond})

	stale := wrap(t, sweeper, connPair(t))
	sweeper.MarkNetworkChange()
	_ = wrap(t, sweeper, connPair(t))

	_ = stale.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err := stale.Read(buf)
	require.ErrorIs(t, err, net.ErrClosed, "stale connection must be closed by the delayed sweep")

	assert.Equal(t, 1, sweeper.sweepAll(), "the fresh connection must survive the stale sweep")
}

func TestMarkNetworkChangeAbortsStaleDials(t *testing.T) {
	sweeper := NewWithConfig(Config{SweepDelay: 10 * time.Millisecond})

	stale := sweeper.StartDial(context.Background())
	defer stale.Release()
	sweeper.MarkNetworkChange()
	fresh := sweeper.StartDial(context.Background())
	defer fresh.Release()

	assert.Eventually(t, func() bool {
		return stale.Ctx().Err() != nil
	}, time.Second, 5*time.Millisecond, "stale dial must be aborted by the delayed sweep")
	assert.NoError(t, fresh.Ctx().Err(), "post-mark dial must not be aborted")
}

func TestConnInheritsDialGeneration(t *testing.T) {
	sweeper := NewWithConfig(Config{SweepDelay: 20 * time.Millisecond})

	// The dial starts before the network change but completes after it: the
	// socket is bound to the old network, so the sweep must still cut it.
	dial := sweeper.StartDial(context.Background())
	defer dial.Release()
	sweeper.MarkNetworkChange()

	wrapped, err := dial.WrapConn(connPair(t))
	require.NoError(t, err)

	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err = wrapped.Read(buf)
	require.ErrorIs(t, err, net.ErrClosed, "old-generation connection must be swept")
}

func TestRepeatedMarksCoalesce(t *testing.T) {
	sweeper := NewWithConfig(Config{SweepDelay: 20 * time.Millisecond})

	first := wrap(t, sweeper, connPair(t))
	sweeper.MarkNetworkChange()
	second := wrap(t, sweeper, connPair(t))
	sweeper.MarkNetworkChange()
	_ = wrap(t, sweeper, connPair(t))

	buf := make([]byte, 1)
	for _, conn := range []net.Conn{first, second} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(buf)
		require.ErrorIs(t, err, net.ErrClosed, "every pre-mark connection must be swept by the rescheduled sweep")
	}
	assert.Equal(t, 1, sweeper.sweepAll(), "only the newest-generation connection may remain")
}

func TestNilSweeperIsNoop(t *testing.T) {
	var sweeper *Sweeper

	conn := connPair(t)
	dial := sweeper.StartDial(context.Background())
	defer dial.Release()

	wrapped, err := dial.WrapConn(conn)
	require.NoError(t, err)
	assert.Equal(t, conn, wrapped, "nil sweeper must return the conn unchanged")
	assert.NoError(t, dial.Ctx().Err(), "nil sweeper must not cancel the dial context")
	assert.Equal(t, 0, sweeper.sweepAll(), "nil sweeper closes nothing")
}

// wrap registers conn with the sweeper through a completed dial.
func wrap(t *testing.T, sweeper *Sweeper, conn net.Conn) net.Conn {
	t.Helper()

	dial := sweeper.StartDial(context.Background())
	defer dial.Release()

	wrapped, err := dial.WrapConn(conn)
	require.NoError(t, err)
	return wrapped
}

// connPair dials a loopback TCP connection and keeps the accepted peer open
// until the test ends: a peer that closed early would make the connection
// unreadable on its own, so a read error after the sweep would prove nothing.
func connPair(t *testing.T) net.Conn {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)

	peer, ok := <-accepted
	require.True(t, ok, "listener must accept the dialed connection")
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Logf("peer close error: %v", err)
		}
	})

	return conn
}

// sweepAll cuts every registration regardless of generation.
func (s *Sweeper) sweepAll() int {
	return s.sweep(math.MaxUint64)
}
