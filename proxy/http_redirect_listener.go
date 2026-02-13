package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// httpRedirectListener wraps a net.Listener and sniffs the first bytes of each connection
// to determine if it's TLS or plain HTTP. Plain HTTP connections are redirected to HTTPS.
type httpRedirectListener struct {
	net.Listener
	logger *log.Logger
}

func (l *httpRedirectListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &httpRedirectConn{Conn: conn, logger: l.logger}, nil
}

// httpRedirectConn wraps a connection and peeks at the first byte to detect TLS vs HTTP.
// If HTTP is detected, it sends a redirect to HTTPS and closes the connection.
type httpRedirectConn struct {
	net.Conn
	logger *log.Logger
	peeked bool
	isTLS  bool
}

func (c *httpRedirectConn) Read(b []byte) (int, error) {
	if c.peeked {
		return c.Conn.Read(b)
	}

	c.peeked = true

	// Peek at first byte
	firstByte := make([]byte, 1)
	n, err := c.Conn.Read(firstByte)
	if err != nil {
		return n, err
	}

	// TLS handshake starts with 0x16 (ContentType: handshake)
	if firstByte[0] == 0x16 {
		c.isTLS = true
		// Copy first byte to output buffer
		copy(b, firstByte)
		// Read remaining bytes
		if len(b) > 1 {
			n2, err := c.Conn.Read(b[1:])
			return n + n2, err
		}
		return n, nil
	}

	// Plain HTTP - handle redirect and close
	c.handleHTTPRedirect(firstByte)
	return 0, io.EOF
}

func (c *httpRedirectConn) handleHTTPRedirect(firstByte []byte) {
	defer func(Conn net.Conn) {
		_ = Conn.Close()
	}(c.Conn)

	// Create a reader that includes the first byte
	reader := io.MultiReader(bytes.NewReader(firstByte), c.Conn)
	bufReader := bufio.NewReader(reader)

	// Parse the HTTP request
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		c.logger.WithError(err).Debug("failed to parse HTTP request for redirect")
		return
	}

	// Create a simple HTTP redirect response
	redirectURL := "https://" + req.Host + req.URL.String()
	response := &http.Response{
		StatusCode: http.StatusMovedPermanently,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	response.Header.Set("Location", redirectURL)
	response.Header.Set("Content-Length", "0")
	if err := response.Write(c.Conn); err != nil {
		c.logger.WithError(err).Warn("failed to write HTTP redirect response")
	}
}
