package grpc

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

// testClient stands for a service client: it records the connection it was
// made for.
type testClient struct {
	conn grpc.ClientConnInterface
}

func newTestClient(conn grpc.ClientConnInterface) *testClient {
	return &testClient{conn: conn}
}

func lazyConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///redial.invalid:443", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// alignedConn returns a RedialConn whose connection was dialed with the aligned
// keepalive, and a Redialer for addr that counts its dials.
func alignedConn(t *testing.T, addr string) (*RedialConn[*testClient], Redialer[*testClient], *atomic.Int32) {
	t.Helper()
	t.Cleanup(func() { ClearStock("/test", addr) })
	r := &RedialConn[*testClient]{}
	conn := lazyConn(t)
	r.Swap(conn, newTestClient(conn), 70*time.Second)
	var dials atomic.Int32
	d := Redialer[*testClient]{
		Name:      "Test",
		Component: "/test",
		Addr:      addr,
		Dial: func(context.Context) (*grpc.ClientConn, time.Duration, error) {
			dials.Add(1)
			return lazyConn(t), stockKeepaliveTime, nil
		},
		NewClient: newTestClient,
	}
	return r, d, &dials
}

// A dial with the stock keepalive is logged only for a client that asked for
// the aligned heartbeat: it dials stock because the server answered stock
// earlier in this session.
func TestLogStockDial(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	const line = "Test answered stock earlier in this session, dialing with the stock keepalive"
	count := func() int {
		n := 0
		for _, e := range hook.AllEntries() {
			if e.Level == log.InfoLevel && strings.Contains(e.Message, line) {
				n++
			}
		}
		return n
	}

	LogStockDial("Test", true, 70*time.Second)
	assert.Zero(t, count(), "an aligned keepalive dial logs nothing")
	LogStockDial("Test", true, stockKeepaliveTime)
	assert.Equal(t, 1, count(), "a stock keepalive dial of an aligned client must log")
	LogStockDial("Test", false, stockKeepaliveTime)
	assert.Equal(t, 1, count(), "a client that does not ask logs nothing")
}

func TestRedialConnZeroValue(t *testing.T) {
	var r RedialConn[*testClient]
	assert.Nil(t, r.Conn(), "no connection")
	assert.Nil(t, r.Client(), "no client")
	assert.NoError(t, r.Close(), "closing an empty RedialConn")
}

func TestRedialConnSwap(t *testing.T) {
	r := &RedialConn[*testClient]{}
	first := lazyConn(t)
	old, swapped := r.Swap(first, newTestClient(first), 70*time.Second)
	assert.True(t, swapped, "the first swap must apply")
	assert.Nil(t, old, "nothing to replace")

	second := lazyConn(t)
	old, swapped = r.Swap(second, newTestClient(second), stockKeepaliveTime)
	assert.True(t, swapped, "a later swap must apply")
	assert.Same(t, first, old, "the replaced connection")
	assert.Same(t, second, r.Conn(), "the new connection")
	assert.Same(t, second, r.Client().conn, "the client of the new connection")
	assert.Equal(t, stockKeepaliveTime, r.Keepalive(), "the keepalive of the new connection")

	require.NoError(t, r.Close())
	assert.Equal(t, connectivity.Shutdown, second.GetState(), "Close must close the connection")
	third := lazyConn(t)
	_, swapped = r.Swap(third, newTestClient(third), stockKeepaliveTime)
	assert.False(t, swapped, "a swap after Close must be refused")
	assert.Same(t, second, r.Conn(), "the closed connection stays")
}

// A stock answer marks the server and redials once with the stock keepalive.
// The old connection is closed after the swap.
func TestRedialConnStockAnswerRedialsOnce(t *testing.T) {
	r, d, dials := alignedConn(t, "stock.example:443")
	old := r.Conn()

	assert.True(t, r.StockAnswer(context.Background(), d), "the first stock answer adds the mark")
	require.Eventually(t, func() bool { return dials.Load() == 1 && r.Conn() != old }, time.Second, 5*time.Millisecond,
		"a stock answer must redial once")
	assert.Equal(t, connectivity.Shutdown, old.GetState(), "the replaced connection must be closed")
	assert.Equal(t, stockKeepaliveTime, r.Keepalive(), "the new connection uses the stock keepalive")
	assert.Same(t, r.Conn(), r.Client().conn, "the client follows the new connection")
	assert.True(t, markedStock(d.Component, d.Addr), "the server is marked stock")

	assert.False(t, r.StockAnswer(context.Background(), d), "a second stock answer finds the mark")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), dials.Load(), "a second stock answer must not redial again")
}

// A connection dialed with the stock keepalive, or a client without a dial,
// is not redialed. The server is marked all the same.
func TestRedialConnStockAnswerNoRedial(t *testing.T) {
	r, d, dials := alignedConn(t, "stockka.example:443")
	conn := lazyConn(t)
	r.Swap(conn, newTestClient(conn), stockKeepaliveTime)
	r.StockAnswer(context.Background(), d)
	assert.True(t, markedStock(d.Component, d.Addr), "the server is marked stock")

	r2, d2, _ := alignedConn(t, "nodial.example:443")
	d2.Dial = nil
	r2.StockAnswer(context.Background(), d2)
	assert.True(t, markedStock(d2.Component, d2.Addr), "the server is marked stock")

	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, dials.Load(), "a stock keepalive connection must not redial")
}

// A redial that fails leaves the connection on the aligned keepalive while the
// mark stays. The next stock answer must redial again, so the connection ends
// on the stock keepalive.
func TestRedialConnStockAnswerRetriesFailedRedial(t *testing.T) {
	r, d, _ := alignedConn(t, "redialfail.example:443")
	old := r.Conn()
	var dials atomic.Int32
	d.Dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		if dials.Add(1) == 1 {
			return nil, 0, errors.New("network down")
		}
		return lazyConn(t), stockKeepaliveTime, nil
	}

	r.StockAnswer(context.Background(), d)
	require.Eventually(t, func() bool { return dials.Load() == 1 && !r.redialing.Load() }, time.Second, 5*time.Millisecond,
		"the first redial must run and fail")
	assert.Same(t, old, r.Conn(), "a failed redial keeps the connection")
	assert.True(t, markedStock(d.Component, d.Addr), "the mark stays after a failed redial")

	r.StockAnswer(context.Background(), d)
	require.Eventually(t, func() bool { return dials.Load() == 2 && r.Conn() != old }, time.Second, 5*time.Millisecond,
		"the next stock answer must redial again")
	assert.Equal(t, stockKeepaliveTime, r.Keepalive(), "the connection ends on the stock keepalive")
	assert.Equal(t, connectivity.Shutdown, old.GetState(), "the replaced connection must be closed")
}

// A mark cleared and set again while a redial runs starts no second redial.
func TestRedialConnOneRedialAtATime(t *testing.T) {
	r, d, _ := alignedConn(t, "busy.example:443")
	release := make(chan struct{})
	var dials atomic.Int32
	d.Dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		dials.Add(1)
		<-release
		return lazyConn(t), stockKeepaliveTime, nil
	}

	r.StockAnswer(context.Background(), d)
	require.Eventually(t, func() bool { return dials.Load() == 1 }, time.Second, 5*time.Millisecond, "the redial must start")
	ClearStock(d.Component, d.Addr)
	r.StockAnswer(context.Background(), d)
	close(release)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), dials.Load(), "a redial in flight must not start another")
}

// A redial that finishes after Close must not leave a live connection behind.
func TestRedialConnRedialAfterCloseClosesNewConn(t *testing.T) {
	r, d, _ := alignedConn(t, "closed.example:443")
	fresh := lazyConn(t)
	d.Dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) { return fresh, stockKeepaliveTime, nil }
	require.NoError(t, r.Close())

	r.redial(context.Background(), d)
	assert.Equal(t, connectivity.Shutdown, fresh.GetState(), "the redialed connection of a closed client must be closed")
}

// An attempt that started on a connection a redial then closed and replaced
// must retry on the new connection. Only a closed client ends the loop.
func TestRedialConnReadyAfterRedialRetries(t *testing.T) {
	r, _, _ := alignedConn(t, "guard.example:443")
	old := r.Conn()
	fresh := lazyConn(t)
	replaced, swapped := r.Swap(fresh, newTestClient(fresh), stockKeepaliveTime)
	require.True(t, swapped)
	require.Same(t, old, replaced)
	require.NoError(t, old.Close())

	var attempts atomic.Int32
	operation := func() error {
		conn := r.Conn()
		if attempts.Add(1) == 1 {
			conn = old // this attempt began before the swap
		}
		return r.Ready(context.Background(), conn, "Test")
	}
	err := Retry(context.Background(), operation, backoff.NewConstantBackOff(time.Millisecond), nil, "test")
	assert.NoError(t, err, "the loop must go on with the new connection")
	assert.Equal(t, int32(2), attempts.Load(), "one retry after the replaced connection")

	require.NoError(t, r.Close())
	err = r.Ready(context.Background(), r.Conn(), "Test")
	var permanent *backoff.PermanentError
	assert.ErrorAs(t, err, &permanent, "a closed client must end the loop")
}
