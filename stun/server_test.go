package stun

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServer creates a STUN server listening on a random port for testing.
// Returns the server, the listener connection (caller must close), and the server address.
func createTestServer(t testing.TB) (*Server, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	server := NewServer([]*net.UDPConn{conn}, "debug")
	return server, conn, conn.LocalAddr().(*net.UDPAddr)
}

// waitForServerReady polls the server with STUN binding requests until it responds.
// This avoids flaky tests on slow CI machines that relied on time.Sleep.
func waitForServerReady(t testing.TB, serverAddr *net.UDPAddr, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	retryInterval := 10 * time.Millisecond

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		require.NoError(t, err)

		_, err = clientConn.Write(msg.Raw)
		require.NoError(t, err)

		_ = clientConn.SetReadDeadline(time.Now().Add(retryInterval))
		n, err := clientConn.Read(buf)
		if err != nil {
			// Timeout or other error, retry
			continue
		}

		response := &stun.Message{Raw: buf[:n]}
		if err := response.Decode(); err != nil {
			continue
		}

		if response.Type == stun.BindingSuccess {
			return // Server is ready
		}
	}

	t.Fatalf("server did not become ready within %v", timeout)
}

func TestServer_BindingRequest(t *testing.T) {
	// Start the STUN server on a random port
	server, listener, serverAddr := createTestServer(t)

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Listen()
	}()

	// Wait for server to be ready
	waitForServerReady(t, serverAddr, 2*time.Second)

	// Create a UDP client
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Build a STUN binding request
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	require.NoError(t, err)

	// Send the request
	_, err = clientConn.Write(msg.Raw)
	require.NoError(t, err)

	// Read the response
	buf := make([]byte, 1500)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	require.NoError(t, err)

	// Parse the response
	response := &stun.Message{Raw: buf[:n]}
	err = response.Decode()
	require.NoError(t, err)

	// Verify it's a binding success
	assert.Equal(t, stun.BindingSuccess, response.Type)

	// Extract the XOR-MAPPED-ADDRESS
	var xorAddr stun.XORMappedAddress
	err = xorAddr.GetFrom(response)
	require.NoError(t, err)

	// Verify the address matches our client's local address
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	assert.Equal(t, clientAddr.IP.String(), xorAddr.IP.String())
	assert.Equal(t, clientAddr.Port, xorAddr.Port)

	// Close listener first to unblock readLoop, then shutdown
	_ = listener.Close()
	err = server.Shutdown()
	require.NoError(t, err)
}

func TestServer_IgnoresNonSTUNPackets(t *testing.T) {
	server, listener, serverAddr := createTestServer(t)

	go func() {
		_ = server.Listen()
	}()

	waitForServerReady(t, serverAddr, 2*time.Second)

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Send non-STUN data
	_, err = clientConn.Write([]byte("hello world"))
	require.NoError(t, err)

	// Try to read response (should timeout since server ignores non-STUN)
	buf := make([]byte, 1500)
	_ = clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = clientConn.Read(buf)
	assert.Error(t, err) // Should be a timeout error

	// Close listener first to unblock readLoop, then shutdown
	_ = listener.Close()
	_ = server.Shutdown()
}

func TestServer_Shutdown(t *testing.T) {
	server, listener, serverAddr := createTestServer(t)

	serverDone := make(chan struct{})
	go func() {
		err := server.Listen()
		assert.True(t, errors.Is(err, ErrServerClosed))
		close(serverDone)
	}()

	waitForServerReady(t, serverAddr, 2*time.Second)

	// Close listener first to unblock readLoop, then shutdown
	_ = listener.Close()

	err := server.Shutdown()
	require.NoError(t, err)

	// Wait for Listen to return
	select {
	case <-serverDone:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

func TestServer_MultipleRequests(t *testing.T) {
	server, listener, serverAddr := createTestServer(t)

	go func() {
		_ = server.Listen()
	}()

	waitForServerReady(t, serverAddr, 2*time.Second)

	// Create multiple clients and send requests
	for i := 0; i < 5; i++ {
		func() {
			clientConn, err := net.DialUDP("udp", nil, serverAddr)
			require.NoError(t, err)
			defer clientConn.Close()

			msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
			require.NoError(t, err)

			_, err = clientConn.Write(msg.Raw)
			require.NoError(t, err)

			buf := make([]byte, 1500)
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			require.NoError(t, err)

			response := &stun.Message{Raw: buf[:n]}
			err = response.Decode()
			require.NoError(t, err)

			assert.Equal(t, stun.BindingSuccess, response.Type)
		}()
	}

	// Close listener first to unblock readLoop, then shutdown
	_ = listener.Close()
	_ = server.Shutdown()
}

func TestServer_ConcurrentClients(t *testing.T) {
	numClients := 100
	requestsPerClient := 5
	maxStartDelay := 100 * time.Millisecond   // Random delay before client starts
	maxRequestDelay := 500 * time.Millisecond // Random delay between requests

	// Remote server to test against via env var STUN_TEST_SERVER
	// Example: STUN_TEST_SERVER=example.netbird.io:3478 go test -v ./stun/... -run ConcurrentClients
	remoteServer := os.Getenv("STUN_TEST_SERVER")

	var serverAddr *net.UDPAddr
	var server *Server
	var listener *net.UDPConn

	if remoteServer != "" {
		// Use remote server
		var err error
		serverAddr, err = net.ResolveUDPAddr("udp", remoteServer)
		require.NoError(t, err)
		t.Logf("Testing against remote server: %s", remoteServer)
	} else {
		// Start local server
		server, listener, serverAddr = createTestServer(t)
		go func() {
			_ = server.Listen()
		}()
		waitForServerReady(t, serverAddr, 2*time.Second)
		t.Logf("Testing against local server: %s", serverAddr)
	}

	var wg sync.WaitGroup
	errorz := make(chan error, numClients*requestsPerClient)
	successCount := make(chan int, numClients)

	startTime := time.Now()

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			// Random delay before starting
			time.Sleep(time.Duration(rand.Int63n(int64(maxStartDelay))))

			clientConn, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				errorz <- fmt.Errorf("client %d: failed to dial: %w", clientID, err)
				return
			}
			defer clientConn.Close()

			success := 0
			for j := 0; j < requestsPerClient; j++ {
				// Random delay between requests
				if j > 0 {
					time.Sleep(time.Duration(rand.Int63n(int64(maxRequestDelay))))
				}

				msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
				if err != nil {
					errorz <- fmt.Errorf("client %d: failed to build request: %w", clientID, err)
					continue
				}

				_, err = clientConn.Write(msg.Raw)
				if err != nil {
					errorz <- fmt.Errorf("client %d: failed to write: %w", clientID, err)
					continue
				}

				buf := make([]byte, 1500)
				_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := clientConn.Read(buf)
				if err != nil {
					errorz <- fmt.Errorf("client %d: failed to read: %w", clientID, err)
					continue
				}

				response := &stun.Message{Raw: buf[:n]}
				if err := response.Decode(); err != nil {
					errorz <- fmt.Errorf("client %d: failed to decode: %w", clientID, err)
					continue
				}

				if response.Type != stun.BindingSuccess {
					errorz <- fmt.Errorf("client %d: unexpected response type: %s", clientID, response.Type)
					continue
				}

				success++
			}
			successCount <- success
		}(i)
	}

	wg.Wait()
	close(errorz)
	close(successCount)

	elapsed := time.Since(startTime)

	totalSuccess := 0
	for count := range successCount {
		totalSuccess += count
	}

	var errs []error
	for err := range errorz {
		errs = append(errs, err)
	}

	totalRequests := numClients * requestsPerClient
	t.Logf("Completed %d/%d requests in %v (%.2f req/s)",
		totalSuccess, totalRequests, elapsed,
		float64(totalSuccess)/elapsed.Seconds())

	if len(errs) > 0 {
		t.Logf("Errors (%d):", len(errs))
		for i, err := range errs {
			if i < 10 { // Only show first 10 errors
				t.Logf("  - %v", err)
			}
		}
	}

	// Require at least 95% success rate
	successRate := float64(totalSuccess) / float64(totalRequests)
	require.GreaterOrEqual(t, successRate, 0.95, "success rate too low: %.2f%%", successRate*100)

	// Cleanup local server if used
	if server != nil {
		// Close listener first to unblock readLoop, then shutdown
		_ = listener.Close()
		_ = server.Shutdown()
	}
}

func TestServer_MultiplePorts(t *testing.T) {
	// Create listeners on two random ports
	conn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	conn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	server := NewServer([]*net.UDPConn{conn1, conn2}, "debug")

	go func() {
		_ = server.Listen()
	}()

	// Wait for server to be ready (checking first port is sufficient)
	waitForServerReady(t, addr1, 2*time.Second)

	// Test requests on both ports
	for _, serverAddr := range []*net.UDPAddr{addr1, addr2} {
		func() {
			clientConn, err := net.DialUDP("udp", nil, serverAddr)
			require.NoError(t, err)
			defer clientConn.Close()

			msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
			require.NoError(t, err)

			_, err = clientConn.Write(msg.Raw)
			require.NoError(t, err)

			buf := make([]byte, 1500)
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			require.NoError(t, err)

			response := &stun.Message{Raw: buf[:n]}
			err = response.Decode()
			require.NoError(t, err)

			assert.Equal(t, stun.BindingSuccess, response.Type)

			var xorAddr stun.XORMappedAddress
			err = xorAddr.GetFrom(response)
			require.NoError(t, err)

			clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
			assert.Equal(t, clientAddr.Port, xorAddr.Port)
		}()
	}

	// Close listeners first to unblock readLoops, then shutdown
	_ = conn1.Close()
	_ = conn2.Close()
	_ = server.Shutdown()
}

// BenchmarkSTUNServer benchmarks the STUN server with concurrent clients
func BenchmarkSTUNServer(b *testing.B) {
	server, listener, serverAddr := createTestServer(b)

	go func() {
		_ = server.Listen()
	}()

	waitForServerReady(b, serverAddr, 2*time.Second)

	// Capture first error atomically - b.Fatal cannot be called from worker goroutines
	var firstErr atomic.Pointer[error]
	setErr := func(err error) {
		firstErr.CompareAndSwap(nil, &err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Stop work if an error has occurred
		if firstErr.Load() != nil {
			return
		}

		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			setErr(err)
			return
		}
		defer clientConn.Close()

		buf := make([]byte, 1500)

		for pb.Next() {
			if firstErr.Load() != nil {
				return
			}

			msg, _ := stun.Build(stun.TransactionID, stun.BindingRequest)
			_, _ = clientConn.Write(msg.Raw)

			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if err != nil {
				setErr(err)
				return
			}

			response := &stun.Message{Raw: buf[:n]}
			if err := response.Decode(); err != nil {
				setErr(err)
				return
			}
		}
	})

	b.StopTimer()

	// Fail after RunParallel completes
	if errPtr := firstErr.Load(); errPtr != nil {
		b.Fatal(*errPtr)
	}

	// Close listener first to unblock readLoop, then shutdown
	_ = listener.Close()
	_ = server.Shutdown()
}
