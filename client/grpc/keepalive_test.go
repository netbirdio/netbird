package grpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/netevents/sweep"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
)

func withClientPeriod(t *testing.T, period time.Duration, ok bool) {
	t.Helper()
	prev := clientPeriod
	clientPeriod = func() (time.Duration, bool) { return period, ok }
	t.Cleanup(func() { clientPeriod = prev })
}

func lazyConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func TestKeepaliveTime(t *testing.T) {
	addr := "keepalive-time.example:443"
	ClearStock("/management", addr)
	t.Cleanup(func() { ClearStock("/management", addr) })

	withClientPeriod(t, 0, false)
	assert.Equal(t, stockKeepaliveTime, keepaliveTime("/management", addr), "no ask, stock")

	withClientPeriod(t, alignedhb.DefaultPeriod, true)
	assert.Equal(t, alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod), keepaliveTime("/management", addr),
		"aligned dial pings after the receive timeout")

	MarkStock("/management", addr)
	assert.Equal(t, stockKeepaliveTime, keepaliveTime("/management", addr), "marked stock")

	ClearStock("/management", addr)
	assert.Equal(t, alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod), keepaliveTime("/management", addr),
		"clearing the mark dials aligned again")
}

func TestStockMarksArePerComponent(t *testing.T) {
	addr := "shared.example:443"
	ClearStock("/management", addr)
	ClearStock("/signal", addr)
	t.Cleanup(func() {
		ClearStock("/management", addr)
		ClearStock("/signal", addr)
	})

	assert.True(t, MarkStock("/management", addr), "first mark is new")
	assert.False(t, MarkStock("/management", addr), "second mark is not")
	assert.True(t, markedStock("/management", addr))
	assert.False(t, markedStock("/signal", addr), "the same address on another component is separate")
}

func TestTCPKeepAliveSwitchesTrackedConn(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })

	var ka TCPKeepAlive
	assert.Zero(t, ka.Applied(), "stock before the answer")
	ka.SetAligned(time.Minute)
	assert.Zero(t, ka.Applied(), "no connection tracked yet")

	ka.Track(conn)
	ka.SetAligned(time.Minute)
	assert.Equal(t, time.Minute, ka.Applied())
	idle, err := keepalive.Idle(conn)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle, "aligned idle at a 60 s period")

	ka.SetAligned(0)
	assert.Equal(t, time.Minute, ka.Applied(), "a bad period changes nothing")

	var nilKA *TCPKeepAlive
	nilKA.Track(conn)
	nilKA.SetAligned(time.Minute)
	assert.Zero(t, nilKA.Applied(), "a nil keepalive does nothing")
}

// TestDialHooksTrackTheTCPSocketWithSweeper covers a client with the network
// monitor on: the sweeper wraps every dialed connection, and the aligned
// answer must still reach the TCP socket below it.
func TestDialHooksTrackTheTCPSocketWithSweeper(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	// Dial plain TCP, as mobile clients do, without the desktop routing hooks.
	t.Setenv("NB_DISABLE_CUSTOM_ROUTING", "true")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	var ka TCPKeepAlive
	cc, err := grpc.NewClient("passthrough:///"+ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		WithDialHooks(sweep.New(), &ka))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	cc.Connect()
	require.Eventually(t, func() bool { return cc.GetState() == connectivity.Ready }, 5*time.Second, 10*time.Millisecond)

	ka.SetAligned(time.Minute)
	assert.Equal(t, time.Minute, ka.Applied(), "the keepalive of the swept connection is switched")
}

func TestRedialConnStockAnswerRedialsOnce(t *testing.T) {
	addr := "redial.example:443"
	ClearStock("/signal", addr)
	t.Cleanup(func() { ClearStock("/signal", addr) })
	withClientPeriod(t, alignedhb.DefaultPeriod, true)

	first, second := lazyConn(t), lazyConn(t)
	var r RedialConn[string]
	_, swapped := r.Swap(first, "first", alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod))
	require.True(t, swapped)

	dials := make(chan struct{}, 4)
	dialer := Redialer[string]{
		Name: "Signal", Component: "/signal", Addr: addr,
		Dial: func(context.Context) (*grpc.ClientConn, time.Duration, error) {
			dials <- struct{}{}
			return second, stockKeepaliveTime, nil
		},
		NewClient: func(grpc.ClientConnInterface) string { return "second" },
	}

	assert.True(t, r.StockAnswer(context.Background(), dialer), "the mark is new")
	require.Eventually(t, func() bool { return r.Conn() == second }, 5*time.Second, 10*time.Millisecond,
		"the redial swaps in the stock connection")
	assert.Equal(t, "second", r.Client())
	assert.Equal(t, stockKeepaliveTime, r.Keepalive())
	assert.True(t, markedStock("/signal", addr))

	<-dials // the one wanted redial

	// A second stock answer on the stock connection neither marks anew nor redials.
	assert.False(t, r.StockAnswer(context.Background(), dialer))
	select {
	case <-dials:
		t.Fatal("a stock connection must not redial again")
	case <-time.After(200 * time.Millisecond):
	}
	assert.Len(t, dials, 0)
}

func TestRedialConnReadyAndClose(t *testing.T) {
	conn := lazyConn(t)
	var r RedialConn[string]
	_, swapped := r.Swap(conn, "client", stockKeepaliveTime)
	require.True(t, swapped)
	assert.NoError(t, r.Ready(context.Background(), conn, "Signal"), "an idle connection is usable")

	require.NoError(t, r.Close())
	assert.NoError(t, r.Close(), "a second Close is a no-op")
	_, swapped = r.Swap(lazyConn(t), "late", stockKeepaliveTime)
	assert.False(t, swapped, "a closed client takes no new connection")
}
