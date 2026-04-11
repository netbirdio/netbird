package inspect

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name    string
		sni     string
		wantSNI string
		wantErr bool
	}{
		{
			name:    "standard domain",
			sni:     "example.com",
			wantSNI: "example.com",
		},
		{
			name:    "subdomain",
			sni:     "api.staging.example.com",
			wantSNI: "api.staging.example.com",
		},
		{
			name:    "mixed case normalized to lowercase",
			sni:     "Example.COM",
			wantSNI: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientHello := buildClientHello(t, tt.sni)

			sni, err := extractSNI(bytes.NewReader(clientHello))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSNI, sni.PunycodeString())
		})
	}
}

func TestExtractSNI_NotTLS(t *testing.T) {
	// HTTP request instead of TLS
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, err := extractSNI(bytes.NewReader(data))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a TLS handshake")
}

func TestExtractSNI_Truncated(t *testing.T) {
	// Just the record header, no body
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	_, err := extractSNI(bytes.NewReader(data))
	require.Error(t, err)
}

func TestExtractSNIFromBytes(t *testing.T) {
	clientHello := buildClientHello(t, "test.example.com")

	sni, err := extractSNIFromBytes(clientHello)
	require.NoError(t, err)
	assert.Equal(t, "test.example.com", sni.PunycodeString())
}

// buildClientHello generates a real TLS ClientHello with the given SNI.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	// Use a pipe to capture the ClientHello bytes
	clientConn, serverConn := net.Pipe()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		done <- buf[:n]
		serverConn.Close()
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})

	// Trigger the handshake (will fail since server isn't TLS, but we capture the ClientHello)
	go func() {
		_ = tlsConn.Handshake()
		tlsConn.Close()
	}()

	clientHello := <-done
	clientConn.Close()

	require.True(t, len(clientHello) > 5, "ClientHello too short")
	require.Equal(t, byte(0x16), clientHello[0], "not a TLS handshake record")

	return clientHello
}
