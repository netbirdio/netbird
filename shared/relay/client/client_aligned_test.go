package client

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordConn) Close() error                     { return nil }
func (c *recordConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordConn) lastWrite() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes[len(c.writes)-1]
}

func newAlignedTestClient(t *testing.T, asking bool) (*Client, *recordConn) {
	t.Helper()
	c := NewClient("rels://relay.example:443", &auth.TokenStore{}, "peer-key", 0)
	conn := &recordConn{}
	c.relayConn = conn
	c.serviceIsRunning = true
	c.log = log.WithField("test", "aligned")
	if asking {
		c.alignedRequest = func() (time.Duration, bool) { return alignedhb.DefaultPeriod, true }
	} else {
		c.alignedRequest = func() (time.Duration, bool) { return 0, false }
	}
	return c, conn
}

func TestGetDialersWSOnlyWhenAligned(t *testing.T) {
	c, _ := newAlignedTestClient(t, true)
	dialers := c.getDialers(TransportModeAuto)
	require.Len(t, dialers, 1, "an aligned mobile client dials WebSocket only")
	assert.IsType(t, ws.Dialer{}, dialers[0])

	c, _ = newAlignedTestClient(t, false)
	dialers = c.getDialers(TransportModeAuto)
	assert.Len(t, dialers, 2, "a stock client keeps the race dialer")
}

func TestHandleHealthCheckAnswersWithPeriod(t *testing.T) {
	c, conn := newAlignedTestClient(t, true)
	hc := healthcheck.NewReceiver(c.log)
	defer hc.Stop()
	flag := newInternalStopFlag()

	// Before the server answers aligned, the answer already carries the
	// requested period, so a server that missed the first frame switches
	// at a later answer.
	c.handleHealthCheck(messages.MarshalHealthcheck(), hc, conn, c.watchSeq, flag)
	period, ok, err := messages.UnmarshalHealthcheckPeriod(conn.lastWrite())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint16(60), period)
	assert.Zero(t, c.AlignedPeriod(), "not aligned before the server frame")

	// The first server frame with the period switches the client.
	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(10), hc, conn, c.watchSeq, flag)
	assert.Equal(t, alignedhb.MinPeriod, c.AlignedPeriod(), "the server period is clamped")

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, conn, c.watchSeq, flag)
	period, ok, err = messages.UnmarshalHealthcheckPeriod(conn.lastWrite())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint16(60), period, "answers carry the confirmed period")
}

func TestHandleHealthCheckStockStaysStock(t *testing.T) {
	c, conn := newAlignedTestClient(t, false)
	hc := healthcheck.NewReceiver(c.log)
	defer hc.Stop()
	flag := newInternalStopFlag()

	c.handleHealthCheck(messages.MarshalHealthcheck(), hc, conn, c.watchSeq, flag)
	_, ok, err := messages.UnmarshalHealthcheckPeriod(conn.lastWrite())
	require.NoError(t, err)
	assert.False(t, ok, "a stock client answers with the stock frame")
	assert.Zero(t, c.AlignedPeriod())

	// A one-byte payload stays stock and never closes the connection.
	oneByte := append(messages.MarshalHealthcheck(), 0x3c)
	c.handleHealthCheck(oneByte, hc, conn, c.watchSeq, flag)
	assert.Zero(t, c.AlignedPeriod())
}

// TestSwitchAlignedSetsKeepaliveOnReadLoopConn checks that the aligned TCP
// keepalive goes on the connection of the read loop that got the server
// frame. c.relayConn may already hold a newer connection while an old read
// loop drains its last frames, so it must not be the target.
func TestSwitchAlignedSetsKeepaliveOnReadLoopConn(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	c, _ := newAlignedTestClient(t, true)
	hc := healthcheck.NewReceiver(c.log)
	defer hc.Stop()
	loopConn := tcpConn(t)

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, loopConn, c.watchSeq, newInternalStopFlag())

	idle, err := keepalive.Idle(loopConn)
	require.NoError(t, err)
	assert.Equal(t, keepalive.AlignedConfig(time.Minute).Idle, idle, "the read loop connection gets the aligned keepalive")
}

// TestHealthCheckOfReplacedConnectionIsIgnored checks that an aligned frame
// the read loop of a replaced connection still drains leaves the current
// connection stock, so its own first aligned frame switches it.
func TestHealthCheckOfReplacedConnectionIsIgnored(t *testing.T) {
	c, conn := newAlignedTestClient(t, true)
	hc := healthcheck.NewReceiver(c.log)
	defer hc.Stop()
	oldSeq := c.watchSeq
	c.watchSeq++

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, conn, oldSeq, newInternalStopFlag())
	assert.Zero(t, c.AlignedPeriod(), "a frame of the replaced connection must not switch the current one")

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, conn, c.watchSeq, newInternalStopFlag())
	assert.Equal(t, time.Minute, c.AlignedPeriod(), "the current connection switches at its own frame")
}

// tcpConn returns the client end of a loopback TCP connection.
func tcpConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- s
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	s, ok := <-accepted
	require.True(t, ok, "accept must succeed")
	t.Cleanup(func() { _ = s.Close() })
	return conn
}

// TestOnlyTheMarkedClientRegistersWithHbwatch checks that a relay client the
// manager did not mark as home, such as a foreign relay, never registers with
// hbwatch, even with aligned server frames; the home client does.
func TestOnlyTheMarkedClientRegistersWithHbwatch(t *testing.T) {
	w := hbwatch.New(wallClock{}, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	relayAligned := func() (registered, aligned bool) {
		for _, st := range w.Snapshot().Streams {
			if st.Service == hbwatch.Relay {
				return true, st.Aligned
			}
		}
		return false, false
	}

	c, conn := newAlignedTestClient(t, true)
	c.stopFlag = newInternalStopFlag()
	hc := healthcheck.NewReceiver(c.log)
	defer hc.Stop()

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, conn, c.watchSeq, c.stopFlag)
	registered, _ := relayAligned()
	assert.False(t, registered, "an unmarked relay client never registers")

	c.WatchHeartbeats()
	registered, aligned := relayAligned()
	assert.True(t, registered, "the home client registers once marked")
	assert.False(t, aligned, "a fresh registration starts unaligned")

	c.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60), hc, conn, c.watchSeq, c.stopFlag)
	_, aligned = relayAligned()
	assert.True(t, aligned, "the next aligned server frame reaches hbwatch")
}

type wallClock struct{}

func (wallClock) Now() time.Time                      { return time.Now() }
func (wallClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }
