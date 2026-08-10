package netsweep

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSweepClosesRegisteredConns(t *testing.T) {
	sweeper := New()

	c1 := sweeper.WrapConn(connPair(t))
	c2 := sweeper.WrapConn(connPair(t))

	assert.Equal(t, 2, sweeper.Sweep(), "both live connections should be closed")

	// The wrappers must report closed now.
	buf := make([]byte, 1)
	_, err := c1.Read(buf)
	assert.Error(t, err, "first connection should be unusable after the sweep")
	_, err = c2.Read(buf)
	assert.Error(t, err, "second connection should be unusable after the sweep")

	assert.Equal(t, 0, sweeper.Sweep(), "second sweep should find nothing")
}

func TestCloseDeregisters(t *testing.T) {
	sweeper := New()

	conn := sweeper.WrapConn(connPair(t))
	require.NoError(t, conn.Close())

	assert.Equal(t, 0, sweeper.Sweep(), "closed connection must leave the registry")
}

func TestCloseIsIdempotent(t *testing.T) {
	sweeper := New()

	conn := sweeper.WrapConn(connPair(t))
	require.NoError(t, conn.Close())
	assert.Error(t, conn.Close(), "double close surfaces the underlying error but must not panic")
}

func TestSweepOnlyAffectsOlderConns(t *testing.T) {
	sweeper := New()

	_ = sweeper.WrapConn(connPair(t))
	assert.Equal(t, 1, sweeper.Sweep())

	// A connection dialed after the sweep must survive until the next one.
	_ = sweeper.WrapConn(connPair(t))
	assert.Equal(t, 1, sweeper.Sweep(), "post-sweep connection belongs to the next sweep")
}

func TestSweepAbortsInFlightDials(t *testing.T) {
	sweeper := New()

	dialCtx, release := sweeper.WrapDialContext(context.Background())
	defer release()

	sweeper.Sweep()

	assert.ErrorIs(t, dialCtx.Err(), context.Canceled, "sweep must cancel the in-flight dial context")
}

func TestReleasedDialIsNotAborted(t *testing.T) {
	sweeper := New()

	// Simulate a dial that finished before the sweep.
	_, release := sweeper.WrapDialContext(context.Background())
	release()

	// A dial still in flight during the sweep.
	pendingCtx, pendingRelease := sweeper.WrapDialContext(context.Background())
	defer pendingRelease()

	sweeper.Sweep()
	assert.ErrorIs(t, pendingCtx.Err(), context.Canceled, "pending dial must be aborted")
}

func TestNilSweeperIsNoop(t *testing.T) {
	var sweeper *Sweeper

	conn := connPair(t)
	assert.Equal(t, conn, sweeper.WrapConn(conn), "nil sweeper must return the conn unchanged")
	assert.Equal(t, 0, sweeper.Sweep(), "nil sweeper closes nothing")

	ctx, release := sweeper.WrapDialContext(context.Background())
	release()
	assert.NoError(t, ctx.Err(), "nil sweeper must not cancel the dial context")
}

// connPair dials a loopback TCP connection against a throwaway listener.
func connPair(t *testing.T) net.Conn {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	})

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	return conn
}
