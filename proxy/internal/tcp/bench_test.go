package tcp

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

// BenchmarkPeekClientHello_TLS measures the overhead of peeking at a real
// TLS ClientHello and extracting the SNI. This is the per-connection cost
// added to every TLS connection on the main listener.
func BenchmarkPeekClientHello_TLS(b *testing.B) {
	// Pre-generate a ClientHello by capturing what crypto/tls sends.
	clientConn, serverConn := net.Pipe()
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = tlsConn.Handshake()
	}()

	var hello []byte
	buf := make([]byte, 16384)
	n, _ := serverConn.Read(buf)
	hello = make([]byte, n)
	copy(hello, buf[:n])
	clientConn.Close()
	serverConn.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		r := bytes.NewReader(hello)
		conn := &readerConn{Reader: r}
		sni, wrapped, err := PeekClientHello(conn)
		if err != nil {
			b.Fatal(err)
		}
		if sni != "app.example.com" {
			b.Fatalf("unexpected SNI: %q", sni)
		}
		// Simulate draining the peeked bytes (what the HTTP server would do).
		_, _ = io.Copy(io.Discard, wrapped)
	}
}

// BenchmarkPeekClientHello_NonTLS measures peek overhead for non-TLS
// connections that hit the fast non-handshake exit path.
func BenchmarkPeekClientHello_NonTLS(b *testing.B) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		r := bytes.NewReader(httpReq)
		conn := &readerConn{Reader: r}
		_, wrapped, err := PeekClientHello(conn)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, wrapped)
	}
}

// BenchmarkPeekedConn_Read measures the read overhead of the peekedConn
// wrapper compared to a plain connection read. The peeked bytes use
// io.MultiReader which adds one indirection per Read call.
func BenchmarkPeekedConn_Read(b *testing.B) {
	data := make([]byte, 4096)
	peeked := make([]byte, 512)
	buf := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		r := bytes.NewReader(data)
		conn := &readerConn{Reader: r}
		pc := newPeekedConn(conn, peeked)
		for {
			_, err := pc.Read(buf)
			if err != nil {
				break
			}
		}
	}
}

// BenchmarkExtractSNI measures just the in-memory SNI parsing cost,
// excluding I/O.
func BenchmarkExtractSNI(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = tlsConn.Handshake()
	}()

	buf := make([]byte, 16384)
	n, _ := serverConn.Read(buf)
	payload := make([]byte, n-tlsRecordHeaderLen)
	copy(payload, buf[tlsRecordHeaderLen:n])
	clientConn.Close()
	serverConn.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		sni := extractSNI(payload)
		if sni != "app.example.com" {
			b.Fatalf("unexpected SNI: %q", sni)
		}
	}
}

// readerConn wraps an io.Reader as a net.Conn for benchmarking.
// Only Read is functional; all other methods are no-ops.
type readerConn struct {
	io.Reader
	net.Conn
}

func (c *readerConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}
