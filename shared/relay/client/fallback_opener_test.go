package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/server"
)

type fakeConn struct {
	net.Conn
	closed chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{closed: make(chan struct{})}
}

func (c *fakeConn) Close() error {
	close(c.closed)
	return nil
}

func newTestConnRace(t *testing.T) *connRace {
	t.Helper()
	raceCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, cancelPreferred := context.WithCancel(raceCtx)
	otherCtx, cancelOther := context.WithCancel(raceCtx)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	return &connRace{
		opener:          &FallbackOpener{},
		peerKey:         "peerKey",
		raceCtx:         raceCtx,
		otherCtx:        otherCtx,
		cancelPreferred: cancelPreferred,
		cancelOther:     cancelOther,
		results:         make(chan raceAttempt, 2),
		fallbackTimer:   timer,
	}
}

func TestHandleResult_PreferredSucceeds(t *testing.T) {
	c := newTestConnRace(t)

	conn := newFakeConn()
	o := c.handleResult(raceAttempt{conn: conn})

	require.True(t, o.done)
	require.NoError(t, o.err)
	require.Same(t, net.Conn(conn), o.conn)
	require.False(t, c.otherStarted, "fallback must not start once the preferred attempt wins")
}

func TestHandleResult_ConnAlreadyExistsIsSuccess(t *testing.T) {
	c := newTestConnRace(t)

	o := c.handleResult(raceAttempt{err: ErrConnAlreadyExists})

	require.True(t, o.done)
	require.ErrorIs(t, o.err, ErrConnAlreadyExists)
	require.False(t, c.otherStarted)
}

func TestHandleResult_PreferredFailsStartsOther(t *testing.T) {
	c := newTestConnRace(t)
	// The fallback attempt opens against a stalling listener so startOther's
	// goroutine blocks on Connect until raceCtx is cancelled by t.Cleanup.
	serverAddr, _ := stallingRelayListener(t)
	c.opener.foreignStore = NewForeignRelaysStore(c.raceCtx, hmacTokenStore, "alice", 1280, newTransportFallback(), func(string) {}, keepUnusedServerTime)
	c.remoteRelayServer = RelayServer{Addr: serverAddr}
	c.preferForeign = false

	o := c.handleResult(raceAttempt{err: errors.New("boom")})

	require.False(t, o.done, "a single failure must not settle the race")
	require.True(t, c.otherStarted, "the fallback attempt must start after the preferred one fails")
	require.EqualError(t, c.lastErr, "boom")
}

func TestHandleResult_BothFailReturnsLastErr(t *testing.T) {
	c := newTestConnRace(t)
	c.otherStarted = true
	c.settled = 1
	c.lastErr = errors.New("first")

	o := c.handleResult(raceAttempt{err: errors.New("second")})

	require.True(t, o.done)
	require.EqualError(t, o.err, "second")
}

func TestOnTimeout_PrefersLastErr(t *testing.T) {
	c := newTestConnRace(t)
	c.lastErr = errors.New("dial failed")

	_, err := c.onTimeout()
	require.EqualError(t, err, "dial failed")
}

func TestOnTimeout_FallsBackToCtxErr(t *testing.T) {
	c := newTestConnRace(t)
	raceCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c.raceCtx = raceCtx

	_, err := c.onTimeout()
	require.ErrorIs(t, err, context.Canceled)
}

func TestDrainLoser_ClosesLateWinner(t *testing.T) {
	r := &FallbackOpener{}
	results := make(chan raceAttempt, 2)

	loser := newFakeConn()
	results <- raceAttempt{conn: loser}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.drainLoser(results, 1, true)
	}()

	select {
	case <-loser.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("losing connection was not closed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainLoser did not return")
	}
}

func TestDrainLoser_NoOtherAttempt(t *testing.T) {
	r := &FallbackOpener{}
	results := make(chan raceAttempt)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.drainLoser(results, 1, false)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainLoser blocked with no outstanding attempt")
	}
}

func startTestRelayServer(t *testing.T, addr string) string {
	t.Helper()

	srv, err := server.NewServer(newManagerTestServerConfig(addr))
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: addr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	require.NoError(t, waitForServerToStart(errChan))
	return addr
}
