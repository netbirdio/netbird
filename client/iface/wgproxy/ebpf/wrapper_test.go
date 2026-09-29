//go:build linux && !android

package ebpf

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPacketConn stands in for the raw socket, so the tests need no
// CAP_NET_RAW and can see whether anything was injected towards WireGuard.
type recordingPacketConn struct {
	writes atomic.Int32
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *recordingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writes.Add(1)
	return len(b), nil
}
func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.IPAddr{IP: localHostNetIPv4} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

// closeCountingConn counts Close calls on the relayed connection.
type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// gatedConn is a relayed connection whose Read ignores Close and only returns
// once released, modelling a reader that notices the teardown late.
type gatedConn struct {
	net.Conn
	release chan struct{}
}

func newGatedConn(t *testing.T) *gatedConn {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	return &gatedConn{Conn: local, release: make(chan struct{})}
}

func (c *gatedConn) Read([]byte) (int, error) {
	<-c.release
	return 0, net.ErrClosed
}

func newTestProxy(t *testing.T) (*WGEBPFProxy, *recordingPacketConn) {
	t.Helper()
	proxy := NewWGEBPFProxy(51820, 1280)
	raw := &recordingPacketConn{}
	proxy.rawConnIPv4 = raw
	return proxy, raw
}

func storedConn(p *WGEBPFProxy, port uint16) (net.Conn, bool) {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()
	conn, ok := p.relayedConnStore[port]
	return conn, ok
}

func storedConns(p *WGEBPFProxy) int {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()
	return len(p.relayedConnStore)
}

func newPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	return local, remote
}

func TestProxyWrapper_CloseReleasesStandbyPort(t *testing.T) {
	proxy, _ := newTestProxy(t)

	for i := range 100 {
		local, _ := newPipe(t)
		wrapper := NewProxyWrapper(proxy)
		require.NoError(t, wrapper.AddRelayedConn(t.Context(), nil, local))
		// A relay that arrives while P2P is active is parked without Work, so
		// its reader never runs and cannot release the port on exit.
		require.NoError(t, wrapper.CloseConn())
		if !assert.Zero(t, storedConns(proxy), "closing standby proxy %d must release its port", i) {
			return
		}
	}
}

func TestProxyWrapper_AddFailureReleasesPort(t *testing.T) {
	proxy := NewWGEBPFProxy(51820, 1280)
	local, _ := newPipe(t)

	wrapper := NewProxyWrapper(proxy)
	err := wrapper.AddRelayedConn(context.Background(), nil, local)
	require.ErrorIs(t, err, errIPv4ConnNotAvailable)
	assert.Zero(t, storedConns(proxy), "a failed setup must roll back the reserved port")
}

func TestProxyWrapper_CloseConnIsIdempotent(t *testing.T) {
	proxy, _ := newTestProxy(t)
	local, _ := newPipe(t)
	remoteConn := &closeCountingConn{Conn: local}

	wrapper := NewProxyWrapper(proxy)
	require.NoError(t, wrapper.AddRelayedConn(t.Context(), nil, remoteConn))
	wrapper.Work()

	assert.NoError(t, wrapper.CloseConn())
	assert.NoError(t, wrapper.CloseConn(), "a repeated close must not fail")
	assert.Equal(t, int32(1), remoteConn.closes.Load(), "the relayed connection must be closed exactly once")
	assert.Zero(t, storedConns(proxy), "the port must be released")
}

// TestProxyWrapper_LateReaderExitKeepsReassignedPort covers a reader that only
// notices its teardown after the allocator has wrapped around and handed the
// released port to another relay. Its deferred cleanup must not evict that
// relay, or WireGuard traffic for it is dropped as "conn already closed".
func TestProxyWrapper_LateReaderExitKeepsReassignedPort(t *testing.T) {
	proxy, _ := newTestProxy(t)

	stale := newGatedConn(t)
	old := NewProxyWrapper(proxy)
	require.NoError(t, old.AddRelayedConn(t.Context(), nil, stale))
	port := uint16(old.EndpointAddr().Port)

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		old.proxyToLocal(old.ctx)
	}()
	require.NoError(t, old.CloseConn())

	proxy.relayedConnMutex.Lock()
	proxy.lastUsedPort = port - 1
	proxy.relayedConnMutex.Unlock()

	fresh, _ := newPipe(t)
	next := NewProxyWrapper(proxy)
	require.NoError(t, next.AddRelayedConn(t.Context(), nil, fresh))
	require.Equal(t, port, uint16(next.EndpointAddr().Port), "the allocator must hand out the released port again")

	close(stale.release)
	<-readerDone

	current, ok := storedConn(proxy, port)
	assert.True(t, ok, "a late reader exit must not release a port owned by another relay")
	assert.Equal(t, fresh, current, "the port must still map to the relay that owns it")
}

// TestProxyWrapper_CloseDoesNotInjectFromPausedReader covers a packet read from
// the relay while the proxy was paused behind P2P. Closing must stop the reader,
// not unpause it into writing the packet to WireGuard.
func TestProxyWrapper_CloseDoesNotInjectFromPausedReader(t *testing.T) {
	proxy, raw := newTestProxy(t)
	local, remote := newPipe(t)

	wrapper := NewProxyWrapper(proxy)
	require.NoError(t, wrapper.AddRelayedConn(t.Context(), nil, local))
	wrapper.Work()
	wrapper.Pause()

	// net.Pipe is synchronous: Write returns once the reader has the packet.
	_, err := remote.Write([]byte("handshake"))
	require.NoError(t, err)

	require.NoError(t, wrapper.CloseConn())
	assert.Never(t, func() bool { return raw.writes.Load() > 0 }, 300*time.Millisecond, 10*time.Millisecond,
		"a closed proxy must not inject the packet it held while paused")
}

// TestProxyWrapper_ConcurrentCloseAndRemoteHangup races the local teardown
// against the remote side hanging up, which makes the reader exit through its
// own cleanup path at the same time.
func TestProxyWrapper_ConcurrentCloseAndRemoteHangup(t *testing.T) {
	proxy, _ := newTestProxy(t)

	var wg sync.WaitGroup
	for range 50 {
		local, remote := newPipe(t)
		wrapper := NewProxyWrapper(proxy)
		require.NoError(t, wrapper.AddRelayedConn(t.Context(), nil, local))
		wrapper.Work()

		wg.Add(3)
		go func() {
			defer wg.Done()
			assert.NoError(t, wrapper.CloseConn())
		}()
		go func() {
			defer wg.Done()
			assert.NoError(t, wrapper.CloseConn())
		}()
		go func() {
			defer wg.Done()
			_ = remote.Close()
		}()
	}
	wg.Wait()

	assert.Eventually(t, func() bool { return storedConns(proxy) == 0 }, 5*time.Second, 10*time.Millisecond,
		"every port must be released once the proxies are closed")
}
