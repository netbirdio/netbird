package stun

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_BindingRequest(t *testing.T) {
	// Start the STUN server on a random port
	server := NewServer("127.0.0.1:0", "debug")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Listen(ctx)
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	// Get the actual address the server is listening on
	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

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
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
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

	// Shutdown server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err = server.Shutdown(shutdownCtx)
	require.NoError(t, err)
}

func TestServer_IgnoresNonSTUNPackets(t *testing.T) {
	server := NewServer("127.0.0.1:0", "debug")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Send non-STUN data
	_, err = clientConn.Write([]byte("hello world"))
	require.NoError(t, err)

	// Try to read response (should timeout since server ignores non-STUN)
	buf := make([]byte, 1500)
	clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = clientConn.Read(buf)
	assert.Error(t, err) // Should be a timeout error

	// Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}

func TestServer_Shutdown(t *testing.T) {
	server := NewServer("127.0.0.1:0", "debug")

	ctx, cancel := context.WithCancel(context.Background())

	serverDone := make(chan struct{})
	go func() {
		_ = server.Listen(ctx)
		close(serverDone)
	}()

	time.Sleep(50 * time.Millisecond)

	// Verify server is listening
	require.NotNil(t, server.conn)

	// Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	cancel() // Cancel the listen context first
	err := server.Shutdown(shutdownCtx)
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
	server := NewServer("127.0.0.1:0", "debug")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

	// Create multiple clients and send requests
	for i := 0; i < 5; i++ {
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)

		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		require.NoError(t, err)

		_, err = clientConn.Write(msg.Raw)
		require.NoError(t, err)

		buf := make([]byte, 1500)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := clientConn.Read(buf)
		require.NoError(t, err)

		response := &stun.Message{Raw: buf[:n]}
		err = response.Decode()
		require.NoError(t, err)

		assert.Equal(t, stun.BindingSuccess, response.Type)

		clientConn.Close()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}

func TestServer_ConcurrentClients(t *testing.T) {
	numClients := 1000
	requestsPerClient := 10
	maxStartDelay := 100 * time.Millisecond // Random delay before client starts
	maxRequestDelay := 1 * time.Second      // Random delay between requests

	// Remote server to test against via env var STUN_TEST_SERVER
	// Example: STUN_TEST_SERVER=example.netbird.io:3478 go test -v ./stun/... -run ConcurrentClients
	remoteServer := os.Getenv("STUN_TEST_SERVER")

	var serverAddr *net.UDPAddr
	var server *Server
	var cancel context.CancelFunc

	if remoteServer != "" {
		// Use remote server
		var err error
		serverAddr, err = net.ResolveUDPAddr("udp", remoteServer)
		require.NoError(t, err)
		t.Logf("Testing against remote server: %s", remoteServer)
	} else {
		// Start local server
		server = NewServer("127.0.0.1:0", "warn")
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		go func() {
			_ = server.Listen(ctx)
		}()
		time.Sleep(50 * time.Millisecond)
		serverAddr = server.conn.LocalAddr().(*net.UDPAddr)
		t.Logf("Testing against local server: %s", serverAddr)
	}

	var wg sync.WaitGroup
	errors := make(chan error, numClients*requestsPerClient)
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
				errors <- fmt.Errorf("client %d: failed to dial: %w", clientID, err)
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
					errors <- fmt.Errorf("client %d: failed to build request: %w", clientID, err)
					continue
				}

				_, err = clientConn.Write(msg.Raw)
				if err != nil {
					errors <- fmt.Errorf("client %d: failed to write: %w", clientID, err)
					continue
				}

				buf := make([]byte, 1500)
				clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := clientConn.Read(buf)
				if err != nil {
					errors <- fmt.Errorf("client %d: failed to read: %w", clientID, err)
					continue
				}

				response := &stun.Message{Raw: buf[:n]}
				if err := response.Decode(); err != nil {
					errors <- fmt.Errorf("client %d: failed to decode: %w", clientID, err)
					continue
				}

				if response.Type != stun.BindingSuccess {
					errors <- fmt.Errorf("client %d: unexpected response type: %s", clientID, response.Type)
					continue
				}

				success++
			}
			successCount <- success
		}(i)
	}

	wg.Wait()
	close(errors)
	close(successCount)

	elapsed := time.Since(startTime)

	totalSuccess := 0
	for count := range successCount {
		totalSuccess += count
	}

	var errs []error
	for err := range errors {
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
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}
}

// BenchmarkSTUNServer benchmarks the STUN server with concurrent clients
func BenchmarkSTUNServer(b *testing.B) {
	server := NewServer("127.0.0.1:0", "error")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			b.Fatal(err)
		}
		defer clientConn.Close()

		buf := make([]byte, 1500)

		for pb.Next() {
			msg, _ := stun.Build(stun.TransactionID, stun.BindingRequest)
			_, _ = clientConn.Write(msg.Raw)

			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			response := &stun.Message{Raw: buf[:n]}
			if err := response.Decode(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.StopTimer()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}
