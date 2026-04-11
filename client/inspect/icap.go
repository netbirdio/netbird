package inspect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	icapVersion     = "ICAP/1.0"
	icapDefaultPort = "1344"
	icapConnTimeout = 30 * time.Second
	icapRWTimeout   = 60 * time.Second
	icapMaxPoolSize = 8
	icapIdleTimeout = 60 * time.Second
	icapMaxRespSize = 4 * 1024 * 1024 // 4 MB
)

// ICAPClient implements an ICAP (RFC 3507) client with persistent connection pooling.
type ICAPClient struct {
	reqModURL  *url.URL
	respModURL *url.URL
	pool       chan *icapConn
	mu         sync.Mutex
	log        *log.Entry
	maxPool    int
}

type icapConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	lastUse time.Time
}

// NewICAPClient creates an ICAP client. Either or both URLs may be nil
// to disable that mode.
func NewICAPClient(logger *log.Entry, cfg *ICAPConfig) *ICAPClient {
	maxPool := cfg.MaxConnections
	if maxPool <= 0 {
		maxPool = icapMaxPoolSize
	}

	return &ICAPClient{
		reqModURL:  cfg.ReqModURL,
		respModURL: cfg.RespModURL,
		pool:       make(chan *icapConn, maxPool),
		log:        logger,
		maxPool:    maxPool,
	}
}

// ReqMod sends an HTTP request to the ICAP REQMOD service for inspection.
// Returns the (possibly modified) request, or the original if ICAP returns 204.
// Returns nil, nil if REQMOD is not configured.
func (c *ICAPClient) ReqMod(req *http.Request) (*http.Request, error) {
	if c.reqModURL == nil {
		return req, nil
	}

	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}

	respBody, err := c.send("REQMOD", c.reqModURL, reqBuf.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	if respBody == nil {
		return req, nil
	}

	modified, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(respBody)))
	if err != nil {
		return nil, fmt.Errorf("parse ICAP modified request: %w", err)
	}
	return modified, nil
}

// RespMod sends an HTTP response to the ICAP RESPMOD service for inspection.
// Returns the (possibly modified) response, or the original if ICAP returns 204.
// Returns nil, nil if RESPMOD is not configured.
func (c *ICAPClient) RespMod(req *http.Request, resp *http.Response) (*http.Response, error) {
	if c.respModURL == nil {
		return resp, nil
	}

	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}

	var respBuf bytes.Buffer
	if err := resp.Write(&respBuf); err != nil {
		return nil, fmt.Errorf("serialize response: %w", err)
	}

	respBody, err := c.send("RESPMOD", c.respModURL, reqBuf.Bytes(), respBuf.Bytes())
	if err != nil {
		return nil, err
	}

	if respBody == nil {
		// 204 No Content: ICAP server didn't modify the response.
		// Reconstruct from the buffered copy since resp.Body was consumed by Write.
		reconstructed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBuf.Bytes())), req)
		if err != nil {
			return nil, fmt.Errorf("reconstruct response after ICAP 204: %w", err)
		}
		return reconstructed, nil
	}

	modified, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBody)), req)
	if err != nil {
		return nil, fmt.Errorf("parse ICAP modified response: %w", err)
	}
	return modified, nil
}

// Close drains and closes all pooled connections.
func (c *ICAPClient) Close() {
	close(c.pool)
	for ic := range c.pool {
		if err := ic.conn.Close(); err != nil {
			c.log.Debugf("close ICAP connection: %v", err)
		}
	}
}

// send executes an ICAP request and returns the encapsulated body from the response.
// Returns nil body for 204 No Content (no modification).
// Retries once on stale pooled connection (EOF on read).
func (c *ICAPClient) send(method string, serviceURL *url.URL, reqData, respData []byte) ([]byte, error) {
	statusCode, headers, body, err := c.trySend(method, serviceURL, reqData, respData)
	if err != nil && isStaleConnErr(err) {
		// Retry once with a fresh connection (stale pool entry).
		c.log.Debugf("ICAP %s: retrying after stale connection: %v", method, err)
		statusCode, headers, body, err = c.trySend(method, serviceURL, reqData, respData)
	}
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case 204:
		return nil, nil
	case 200:
		return body, nil
	default:
		c.log.Debugf("ICAP %s returned status %d, headers: %v", method, statusCode, headers)
		return nil, fmt.Errorf("ICAP %s: status %d", method, statusCode)
	}
}

func (c *ICAPClient) trySend(method string, serviceURL *url.URL, reqData, respData []byte) (int, textproto.MIMEHeader, []byte, error) {
	ic, err := c.getConn(serviceURL)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("get ICAP connection: %w", err)
	}

	if err := c.writeRequest(ic, method, serviceURL, reqData, respData); err != nil {
		if closeErr := ic.conn.Close(); closeErr != nil {
			c.log.Debugf("close ICAP conn after write error: %v", closeErr)
		}
		return 0, nil, nil, fmt.Errorf("write ICAP %s: %w", method, err)
	}

	statusCode, headers, body, err := c.readResponse(ic)
	if err != nil {
		if closeErr := ic.conn.Close(); closeErr != nil {
			c.log.Debugf("close ICAP conn after read error: %v", closeErr)
		}
		return 0, nil, nil, fmt.Errorf("read ICAP response: %w", err)
	}

	c.putConn(ic)
	return statusCode, headers, body, nil
}

func isStaleConnErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") || strings.Contains(s, "broken pipe") || strings.Contains(s, "connection reset")
}

func (c *ICAPClient) writeRequest(ic *icapConn, method string, serviceURL *url.URL, reqData, respData []byte) error {
	if err := ic.conn.SetWriteDeadline(time.Now().Add(icapRWTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	// For RESPMOD, split the serialized HTTP response into headers and body.
	// The body must be sent chunked per RFC 3507.
	var respHdr, respBody []byte
	if respData != nil {
		if idx := bytes.Index(respData, []byte("\r\n\r\n")); idx >= 0 {
			respHdr = respData[:idx+4] // include the \r\n\r\n separator
			respBody = respData[idx+4:]
		} else {
			respHdr = respData
		}
	}

	var buf bytes.Buffer

	// Request line
	fmt.Fprintf(&buf, "%s %s %s\r\n", method, serviceURL.String(), icapVersion)

	// Headers
	host := serviceURL.Host
	fmt.Fprintf(&buf, "Host: %s\r\n", host)
	fmt.Fprintf(&buf, "Connection: keep-alive\r\n")
	fmt.Fprintf(&buf, "Allow: 204\r\n")

	// Build Encapsulated header
	offset := 0
	var encapParts []string
	if reqData != nil {
		encapParts = append(encapParts, fmt.Sprintf("req-hdr=%d", offset))
		offset += len(reqData)
	}
	if respHdr != nil {
		encapParts = append(encapParts, fmt.Sprintf("res-hdr=%d", offset))
		offset += len(respHdr)
	}
	if len(respBody) > 0 {
		encapParts = append(encapParts, fmt.Sprintf("res-body=%d", offset))
	} else {
		encapParts = append(encapParts, fmt.Sprintf("null-body=%d", offset))
	}
	fmt.Fprintf(&buf, "Encapsulated: %s\r\n", strings.Join(encapParts, ", "))
	fmt.Fprintf(&buf, "\r\n")

	// Encapsulated sections
	if reqData != nil {
		buf.Write(reqData)
	}
	if respHdr != nil {
		buf.Write(respHdr)
	}
	// Body in chunked encoding (only when there is an actual body section).
	// Per RFC 3507 Section 4.4.1, null-body must not include any entity data.
	if len(respBody) > 0 {
		fmt.Fprintf(&buf, "%x\r\n", len(respBody))
		buf.Write(respBody)
		buf.WriteString("\r\n")
		buf.WriteString("0\r\n\r\n")
	}

	_, err := ic.conn.Write(buf.Bytes())
	return err
}

func (c *ICAPClient) readResponse(ic *icapConn) (int, textproto.MIMEHeader, []byte, error) {
	if err := ic.conn.SetReadDeadline(time.Now().Add(icapRWTimeout)); err != nil {
		return 0, nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	tp := textproto.NewReader(ic.reader)

	// Status line: "ICAP/1.0 200 OK"
	statusLine, err := tp.ReadLine()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read status line: %w", err)
	}

	statusCode, err := parseICAPStatus(statusLine)
	if err != nil {
		return 0, nil, nil, err
	}

	// Headers
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return statusCode, nil, nil, fmt.Errorf("read ICAP headers: %w", err)
	}

	if statusCode == 204 {
		return statusCode, headers, nil, nil
	}

	// Read encapsulated body based on Encapsulated header
	body, err := c.readEncapsulatedBody(ic.reader, headers)
	if err != nil {
		return statusCode, headers, nil, fmt.Errorf("read encapsulated body: %w", err)
	}

	return statusCode, headers, body, nil
}

func (c *ICAPClient) readEncapsulatedBody(r *bufio.Reader, headers textproto.MIMEHeader) ([]byte, error) {
	encap := headers.Get("Encapsulated")
	if encap == "" {
		return nil, nil
	}

	// Find the body offset from the Encapsulated header.
	// The last section with a non-zero offset is the body.
	// Read everything from the reader as the encapsulated content.
	var totalSize int
	parts := strings.Split(encap, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		offset, err := strconv.Atoi(strings.TrimSpace(part[eqIdx+1:]))
		if err != nil {
			continue
		}
		if offset > totalSize {
			totalSize = offset
		}
	}

	// Read all available encapsulated data (headers + body)
	// The body section uses chunked encoding per RFC 3507
	var buf bytes.Buffer
	if totalSize > 0 {
		// Read the header sections (everything before the body offset)
		headerBytes := make([]byte, totalSize)
		if _, err := io.ReadFull(r, headerBytes); err != nil {
			return nil, fmt.Errorf("read encapsulated headers: %w", err)
		}
		buf.Write(headerBytes)
	}

	// Read chunked body
	chunked := newChunkedReader(r)
	body, err := io.ReadAll(io.LimitReader(chunked, icapMaxRespSize))
	if err != nil {
		return nil, fmt.Errorf("read chunked body: %w", err)
	}
	buf.Write(body)

	return buf.Bytes(), nil
}

func (c *ICAPClient) getConn(serviceURL *url.URL) (*icapConn, error) {
	// Try to get a pooled connection
	for {
		select {
		case ic := <-c.pool:
			if time.Since(ic.lastUse) > icapIdleTimeout {
				if err := ic.conn.Close(); err != nil {
					c.log.Debugf("close idle ICAP connection: %v", err)
				}
				continue
			}
			return ic, nil
		default:
			return c.dialConn(serviceURL)
		}
	}
}

func (c *ICAPClient) putConn(ic *icapConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ic.lastUse = time.Now()
	select {
	case c.pool <- ic:
	default:
		// Pool full, close connection.
		if err := ic.conn.Close(); err != nil {
			c.log.Debugf("close excess ICAP connection: %v", err)
		}
	}
}

func (c *ICAPClient) dialConn(serviceURL *url.URL) (*icapConn, error) {
	host := serviceURL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, icapDefaultPort)
	}

	conn, err := net.DialTimeout("tcp", host, icapConnTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial ICAP %s: %w", host, err)
	}

	return &icapConn{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		lastUse: time.Now(),
	}, nil
}

func parseICAPStatus(line string) (int, error) {
	// "ICAP/1.0 200 OK"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed ICAP status line: %q", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("parse ICAP status code %q: %w", parts[1], err)
	}
	return code, nil
}

// chunkedReader reads ICAP chunked encoding (same as HTTP chunked, terminated by "0\r\n\r\n").
type chunkedReader struct {
	r         *bufio.Reader
	remaining int
	done      bool
}

func newChunkedReader(r *bufio.Reader) *chunkedReader {
	return &chunkedReader{r: r}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.done {
		return 0, io.EOF
	}

	if cr.remaining == 0 {
		// Read chunk size line
		line, err := cr.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)

		// Strip any chunk extensions
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}

		size, err := strconv.ParseInt(line, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parse chunk size %q: %w", line, err)
		}

		if size == 0 {
			cr.done = true
			// Consume trailing \r\n
			_, _ = cr.r.ReadString('\n')
			return 0, io.EOF
		}

		if size < 0 || size > icapMaxRespSize {
			return 0, fmt.Errorf("chunk size %d out of range (max %d)", size, icapMaxRespSize)
		}

		cr.remaining = int(size)
	}

	toRead := len(p)
	if toRead > cr.remaining {
		toRead = cr.remaining
	}

	n, err := cr.r.Read(p[:toRead])
	cr.remaining -= n

	if cr.remaining == 0 {
		// Consume chunk-terminating \r\n
		_, _ = cr.r.ReadString('\n')
	}

	return n, err
}
