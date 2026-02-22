package udp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestRelay_BasicPacketExchange(t *testing.T) {
	// Set up a UDP backend that echoes packets.
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	// Set up the relay's public-facing listener.
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	backendAddr := backend.LocalAddr().String()

	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	relay := New(ctx, logger, listener, backendAddr, "", dialFunc, 0, 0, 0)
	go relay.Serve()
	defer relay.Close()

	// Create a client and send a packet to the relay.
	client, err := net.Dial("udp", listener.LocalAddr().String())
	require.NoError(t, err)
	defer client.Close()

	testData := []byte("hello UDP relay")
	_, err = client.Write(testData)
	require.NoError(t, err)

	// Read the echoed response.
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "should receive echoed packet")
}

func TestRelay_MultipleClients(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	relay := New(ctx, logger, listener, backend.LocalAddr().String(), "", dialFunc, 0, 0, 0)
	go relay.Serve()
	defer relay.Close()

	// Two clients, each should get their own session.
	for i, msg := range []string{"client-1", "client-2"} {
		client, err := net.Dial("udp", listener.LocalAddr().String())
		require.NoError(t, err, "client %d", i)
		defer client.Close()

		_, err = client.Write([]byte(msg))
		require.NoError(t, err)

		if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		require.NoError(t, err, "client %d read", i)
		assert.Equal(t, msg, string(buf[:n]), "client %d should get own echo", i)
	}

	// Verify two sessions were created.
	relay.mu.RLock()
	sessionCount := len(relay.sessions)
	relay.mu.RUnlock()
	assert.Equal(t, 2, sessionCount, "should have two sessions")
}

func TestRelay_Close(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	relay := New(ctx, logger, listener, "127.0.0.1:9999", "", dialFunc, 0, 0, 0)

	done := make(chan struct{})
	go func() {
		relay.Serve()
		close(done)
	}()

	relay.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestRelay_SessionCleanup(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	relay := New(ctx, logger, listener, backend.LocalAddr().String(), "", dialFunc, 0, 0, 0)
	go relay.Serve()
	defer relay.Close()

	// Create a session.
	client, err := net.Dial("udp", listener.LocalAddr().String())
	require.NoError(t, err)
	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_, err = client.Read(buf)
	require.NoError(t, err)
	client.Close()

	// Verify session exists.
	relay.mu.RLock()
	assert.Equal(t, 1, len(relay.sessions))
	relay.mu.RUnlock()

	// Make session appear idle by setting lastSeen to the past.
	relay.mu.Lock()
	for _, sess := range relay.sessions {
		sess.lastSeen.Store(time.Now().Add(-2 * DefaultSessionTTL).UnixNano())
	}
	relay.mu.Unlock()

	// Trigger cleanup manually.
	relay.cleanupIdleSessions()

	relay.mu.RLock()
	assert.Equal(t, 0, len(relay.sessions), "idle sessions should be cleaned up")
	relay.mu.RUnlock()
}

// TestRelay_CloseAndRecreate verifies that closing a relay and creating a new
// one on the same port works cleanly (simulates port mapping modify cycle).
func TestRelay_CloseAndRecreate(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	// First relay.
	ln1, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	relay1 := New(ctx, logger, ln1, backend.LocalAddr().String(), "", dialFunc, 0, 0, 0)
	go relay1.Serve()

	client1, err := net.Dial("udp", ln1.LocalAddr().String())
	require.NoError(t, err)
	_, err = client1.Write([]byte("relay1"))
	require.NoError(t, err)
	require.NoError(t, client1.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1024)
	n, err := client1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "relay1", string(buf[:n]))
	client1.Close()

	// Close first relay.
	relay1.Close()

	// Second relay on same port.
	port := ln1.LocalAddr().(*net.UDPAddr).Port
	ln2, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)

	relay2 := New(ctx, logger, ln2, backend.LocalAddr().String(), "", dialFunc, 0, 0, 0)
	go relay2.Serve()
	defer relay2.Close()

	client2, err := net.Dial("udp", ln2.LocalAddr().String())
	require.NoError(t, err)
	defer client2.Close()
	_, err = client2.Write([]byte("relay2"))
	require.NoError(t, err)
	require.NoError(t, client2.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err = client2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "relay2", string(buf[:n]), "second relay should work on same port")
}

func TestRelay_SessionLimit(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	// Create a relay with a max of 2 sessions.
	relay := New(ctx, logger, listener, backend.LocalAddr().String(), "", dialFunc, 0, 0, 2)
	go relay.Serve()
	defer relay.Close()

	// Create 2 clients to fill up the session limit.
	for i := range 2 {
		client, err := net.Dial("udp", listener.LocalAddr().String())
		require.NoError(t, err, "client %d", i)
		defer client.Close()

		_, err = client.Write([]byte("hello"))
		require.NoError(t, err)

		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		_, err = client.Read(buf)
		require.NoError(t, err, "client %d should get response", i)
	}

	relay.mu.RLock()
	assert.Equal(t, 2, len(relay.sessions), "should have exactly 2 sessions")
	relay.mu.RUnlock()

	// Third client should get its packet dropped (session creation fails).
	client3, err := net.Dial("udp", listener.LocalAddr().String())
	require.NoError(t, err)
	defer client3.Close()

	_, err = client3.Write([]byte("should be dropped"))
	require.NoError(t, err)

	require.NoError(t, client3.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 1024)
	_, err = client3.Read(buf)
	assert.Error(t, err, "third client should time out because session was rejected")

	relay.mu.RLock()
	assert.Equal(t, 2, len(relay.sessions), "session count should not exceed limit")
	relay.mu.RUnlock()
}

// testObserver records UDP session lifecycle events for test assertions.
type testObserver struct {
	mu       sync.Mutex
	started  int
	ended    int
	rejected int
	dialErr  int
	packets  int
	bytes    int
}

func (o *testObserver) UDPSessionStarted(string)  { o.mu.Lock(); o.started++; o.mu.Unlock() }
func (o *testObserver) UDPSessionEnded(string)     { o.mu.Lock(); o.ended++; o.mu.Unlock() }
func (o *testObserver) UDPSessionDialError(string) { o.mu.Lock(); o.dialErr++; o.mu.Unlock() }
func (o *testObserver) UDPSessionRejected(string)  { o.mu.Lock(); o.rejected++; o.mu.Unlock() }
func (o *testObserver) UDPPacketRelayed(_ types.RelayDirection, b int) {
	o.mu.Lock()
	o.packets++
	o.bytes += b
	o.mu.Unlock()
}

func TestRelay_CloseFiresObserverEnded(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	obs := &testObserver{}
	relay := New(ctx, logger, listener, backend.LocalAddr().String(), "test-acct", dialFunc, 0, 0, 0)
	relay.SetObserver(obs)
	go relay.Serve()

	// Create two sessions.
	for i := range 2 {
		client, err := net.Dial("udp", listener.LocalAddr().String())
		require.NoError(t, err, "client %d", i)

		_, err = client.Write([]byte("hello"))
		require.NoError(t, err)

		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		_, err = client.Read(buf)
		require.NoError(t, err)
		client.Close()
	}

	obs.mu.Lock()
	assert.Equal(t, 2, obs.started, "should have 2 started events")
	obs.mu.Unlock()

	// Close should fire UDPSessionEnded for all remaining sessions.
	relay.Close()

	obs.mu.Lock()
	assert.Equal(t, 2, obs.ended, "Close should fire UDPSessionEnded for each session")
	obs.mu.Unlock()
}

func TestRelay_SessionRateLimit(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewEntry(log.StandardLogger())
	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, address)
	}

	obs := &testObserver{}
	// High max sessions (1000) but the relay uses a rate limiter internally
	// (default: 50/s burst 100). We exhaust the burst by creating sessions
	// rapidly, then verify that subsequent creates are rejected.
	relay := New(ctx, logger, listener, backend.LocalAddr().String(), "test-acct", dialFunc, 0, 0, 1000)
	relay.SetObserver(obs)
	go relay.Serve()
	defer relay.Close()

	// Exhaust the burst by calling getOrCreateSession directly with
	// synthetic addresses. This is faster than real UDP round-trips.
	for i := range sessionCreateBurst + 20 {
		addr := &net.UDPAddr{IP: net.IPv4(10, 0, byte(i/256), byte(i%256)), Port: 10000 + i}
		_, _ = relay.getOrCreateSession(addr)
	}

	obs.mu.Lock()
	rejected := obs.rejected
	obs.mu.Unlock()

	assert.Greater(t, rejected, 0, "some sessions should be rate-limited")
}
