package netrelay

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// tcpPair returns two connected loopback TCP conns.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	type result struct {
		c   *net.TCPConn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		ch <- result{c.(*net.TCPConn), nil}
	}()

	dial, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	r := <-ch
	require.NoError(t, r.err)
	return dial.(*net.TCPConn), r.c
}

// TestRelayHalfClose exercises the shutdown(SHUT_WR) scenario that the naive
// cancel-both-on-first-EOF pattern breaks. Client A shuts down its write
// side; B must still be able to write a full response and A must receive
// all of it before its read returns EOF.
func TestRelayHalfClose(t *testing.T) {
	// Real peer pairs for each side of the relay. We relay between relayA
	// and relayB. Peer A talks through relayA; peer B talks through relayB.
	peerA, relayA := tcpPair(t)
	relayB, peerB := tcpPair(t)

	defer peerA.Close()
	defer peerB.Close()

	// Bound blocking reads/writes so a broken relay fails the test instead of
	// hanging the test process.
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, peerA.SetDeadline(deadline))
	require.NoError(t, peerB.SetDeadline(deadline))

	ctx := t.Context()

	done := make(chan struct{})
	go func() {
		Relay(ctx, relayA, relayB, Options{})
		close(done)
	}()

	// Peer A sends a request, then half-closes its write side.
	req := []byte("request-payload")
	_, err := peerA.Write(req)
	require.NoError(t, err)
	require.NoError(t, peerA.CloseWrite())

	// Peer B reads the request to EOF (FIN must have propagated).
	got, err := io.ReadAll(peerB)
	require.NoError(t, err)
	require.Equal(t, req, got)

	// Peer B writes its response; peer A must receive all of it even though
	// peer A's write side is already closed.
	resp := make([]byte, 64*1024)
	for i := range resp {
		resp[i] = byte(i)
	}
	_, err = peerB.Write(resp)
	require.NoError(t, err)
	require.NoError(t, peerB.Close())

	gotResp, err := io.ReadAll(peerA)
	require.NoError(t, err)
	require.Equal(t, resp, gotResp)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return")
	}
}

// TestRelayFullDuplex verifies bidirectional copy in the simple case.
func TestRelayFullDuplex(t *testing.T) {
	peerA, relayA := tcpPair(t)
	relayB, peerB := tcpPair(t)
	defer peerA.Close()
	defer peerB.Close()

	// Bound blocking reads/writes so a broken relay fails the test instead of
	// hanging the test process.
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, peerA.SetDeadline(deadline))
	require.NoError(t, peerB.SetDeadline(deadline))

	ctx := t.Context()

	done := make(chan struct{})
	go func() {
		Relay(ctx, relayA, relayB, Options{})
		close(done)
	}()

	type result struct {
		got []byte
		err error
	}
	resA := make(chan result, 1)
	resB := make(chan result, 1)

	msgAB := []byte("hello-from-a")
	msgBA := []byte("hello-from-b")

	go func() {
		if _, err := peerA.Write(msgAB); err != nil {
			resA <- result{err: err}
			return
		}
		buf := make([]byte, len(msgBA))
		_, err := io.ReadFull(peerA, buf)
		resA <- result{got: buf, err: err}
		_ = peerA.Close()
	}()

	go func() {
		if _, err := peerB.Write(msgBA); err != nil {
			resB <- result{err: err}
			return
		}
		buf := make([]byte, len(msgAB))
		_, err := io.ReadFull(peerB, buf)
		resB <- result{got: buf, err: err}
		_ = peerB.Close()
	}()

	a, b := <-resA, <-resB
	require.NoError(t, a.err)
	require.Equal(t, msgBA, a.got)
	require.NoError(t, b.err)
	require.Equal(t, msgAB, b.got)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return")
	}
}

// TestRelayNoHalfCloseFallback ensures Relay terminates when the underlying
// conns don't support CloseWrite (e.g. net.Pipe). Without the fallback to
// cancel-both-on-first-EOF, the second direction would block forever.
func TestRelayNoHalfCloseFallback(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a1.Close()
	defer b1.Close()

	ctx := t.Context()
	done := make(chan struct{})
	go func() {
		Relay(ctx, a2, b2, Options{})
		close(done)
	}()

	// Close peer A's side; a2's Read will return EOF.
	require.NoError(t, a1.Close())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not terminate when half-close is unsupported")
	}
}

// TestRelayIdleTimeout ensures the idle watchdog tears down a silent flow.
func TestRelayIdleTimeout(t *testing.T) {
	peerA, relayA := tcpPair(t)
	relayB, peerB := tcpPair(t)
	defer peerA.Close()
	defer peerB.Close()

	ctx := t.Context()

	const idle = 150 * time.Millisecond

	start := time.Now()
	done := make(chan struct{})
	go func() {
		Relay(ctx, relayA, relayB, Options{IdleTimeout: idle})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on idle")
	}

	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, idle,
		"relay must not close before the idle timeout elapses")
	require.Less(t, elapsed, idle+500*time.Millisecond,
		"relay should close shortly after the idle timeout")
}
