package stun

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_BindingRequest(t *testing.T) {
	// Start the STUN server on a random port
	server := NewServer("127.0.0.1:0")

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
	server := NewServer("127.0.0.1:0")

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
	server := NewServer("127.0.0.1:0")

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
	server := NewServer("127.0.0.1:0")

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
