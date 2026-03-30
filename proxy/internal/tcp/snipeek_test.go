package tcp

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeekClientHello_ValidSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	const expectedSNI = "example.com"
	trailingData := []byte("trailing data after handshake")

	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         expectedSNI,
			InsecureSkipVerify: true, //nolint:gosec
		})
		// The Handshake will send the ClientHello. It will fail because
		// our server side isn't doing a real TLS handshake, but that's
		// fine: we only need the ClientHello to be sent.
		_ = tlsConn.Handshake()
	}()

	sni, wrapped, err := PeekClientHello(serverConn)
	require.NoError(t, err)
	assert.Equal(t, expectedSNI, sni, "should extract SNI from ClientHello")
	assert.NotNil(t, wrapped, "wrapped connection should not be nil")

	// Verify the wrapped connection replays the peeked bytes.
	// Read the first 5 bytes (TLS record header) to confirm replay.
	buf := make([]byte, 5)
	n, err := wrapped.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, byte(contentTypeHandshake), buf[0], "first byte should be TLS handshake content type")

	// Write trailing data from the client side and verify it arrives
	// through the wrapped connection after the peeked bytes.
	go func() {
		_, _ = clientConn.Write(trailingData)
	}()

	// Drain the rest of the peeked ClientHello first.
	peekedRest := make([]byte, 16384)
	_, _ = wrapped.Read(peekedRest)

	got := make([]byte, len(trailingData))
	n, err = io.ReadFull(wrapped, got)
	require.NoError(t, err)
	assert.Equal(t, trailingData, got[:n])
}

func TestPeekClientHello_MultipleSNIs(t *testing.T) {
	tests := []struct {
		name        string
		serverName  string
		expectedSNI string
	}{
		{"simple domain", "example.com", "example.com"},
		{"subdomain", "sub.example.com", "sub.example.com"},
		{"deep subdomain", "a.b.c.example.com", "a.b.c.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			go func() {
				tlsConn := tls.Client(clientConn, &tls.Config{
					ServerName:         tt.serverName,
					InsecureSkipVerify: true, //nolint:gosec
				})
				_ = tlsConn.Handshake()
			}()

			sni, wrapped, err := PeekClientHello(serverConn)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSNI, sni)
			assert.NotNil(t, wrapped)
		})
	}
}

func TestPeekClientHello_NonTLSData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send plain HTTP data (not TLS).
	httpData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	go func() {
		_, _ = clientConn.Write(httpData)
	}()

	sni, wrapped, err := PeekClientHello(serverConn)
	require.NoError(t, err)
	assert.Empty(t, sni, "should return empty SNI for non-TLS data")
	assert.NotNil(t, wrapped)

	// Verify the wrapped connection still provides the original data.
	buf := make([]byte, len(httpData))
	n, err := io.ReadFull(wrapped, buf)
	require.NoError(t, err)
	assert.Equal(t, httpData, buf[:n], "wrapped connection should replay original data")
}

func TestPeekClientHello_TruncatedHeader(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	// Write only 3 bytes then close, fewer than the 5-byte TLS header.
	go func() {
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01})
		clientConn.Close()
	}()

	_, _, err := PeekClientHello(serverConn)
	assert.Error(t, err, "should error on truncated header")
}

func TestPeekClientHello_TruncatedPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	// Write a valid TLS header claiming 100 bytes, but only send 10.
	go func() {
		header := []byte{0x16, 0x03, 0x01, 0x00, 0x64} // 100 bytes claimed
		_, _ = clientConn.Write(header)
		_, _ = clientConn.Write(make([]byte, 10))
		clientConn.Close()
	}()

	_, _, err := PeekClientHello(serverConn)
	assert.Error(t, err, "should error on truncated payload")
}

func TestPeekClientHello_ZeroLengthRecord(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// TLS handshake header with zero-length payload.
	go func() {
		_, _ = clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	}()

	sni, wrapped, err := PeekClientHello(serverConn)
	require.NoError(t, err)
	assert.Empty(t, sni)
	assert.NotNil(t, wrapped)
}

func TestExtractSNI_InvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{0x01, 0x00}},
		{"wrong handshake type", []byte{0x02, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00}},
		{"truncated client hello", []byte{0x01, 0x00, 0x00, 0x20}}, // claims 32 bytes but has none
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Empty(t, extractSNI(tt.payload))
		})
	}
}

func TestPeekedConn_CloseWrite(t *testing.T) {
	t.Run("delegates to underlying TCPConn", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				accepted <- c
			}
		}()

		client, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer client.Close()

		server := <-accepted
		defer server.Close()

		wrapped := newPeekedConn(server, []byte("peeked"))

		// CloseWrite should succeed on a real TCP connection.
		err = wrapped.CloseWrite()
		assert.NoError(t, err)

		// The client should see EOF on reads after CloseWrite.
		buf := make([]byte, 1)
		_, err = client.Read(buf)
		assert.Equal(t, io.EOF, err, "client should see EOF after half-close")
	})

	t.Run("no-op on non-halfcloser", func(t *testing.T) {
		// net.Pipe does not implement CloseWrite.
		_, server := net.Pipe()
		defer server.Close()

		wrapped := newPeekedConn(server, []byte("peeked"))
		err := wrapped.CloseWrite()
		assert.NoError(t, err, "should be no-op on non-halfcloser")
	})
}

func TestPeekedConn_ReplayAndPassthrough(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	peeked := []byte("peeked-data")
	subsequent := []byte("subsequent-data")

	wrapped := newPeekedConn(serverConn, peeked)

	go func() {
		_, _ = clientConn.Write(subsequent)
	}()

	// Read should return peeked data first.
	buf := make([]byte, len(peeked))
	n, err := io.ReadFull(wrapped, buf)
	require.NoError(t, err)
	assert.Equal(t, peeked, buf[:n])

	// Then subsequent data from the real connection.
	buf = make([]byte, len(subsequent))
	n, err = io.ReadFull(wrapped, buf)
	require.NoError(t, err)
	assert.Equal(t, subsequent, buf[:n])
}
