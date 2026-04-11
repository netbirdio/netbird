package inspect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/domain"
)

const (
	headerUpgrade  = "Upgrade"
	valueWebSocket = "websocket"
)

// inspectHTTP runs the HTTP inspection pipeline on decrypted traffic.
// It handles HTTP/1.1 (request-response loop), HTTP/2 (via Go stdlib reverse proxy),
// and WebSocket upgrade detection.
func (p *Proxy) inspectHTTP(ctx context.Context, client, remote net.Conn, dst netip.AddrPort, sni domain.Domain, src SourceInfo, proto string) error {
	if proto == "h2" {
		return p.inspectH2(ctx, client, remote, dst, sni, src)
	}
	return p.inspectH1(ctx, client, remote, dst, sni, src)
}

// inspectH1 handles HTTP/1.1 request-response inspection in a loop.
func (p *Proxy) inspectH1(ctx context.Context, client, remote net.Conn, dst netip.AddrPort, sni domain.Domain, src SourceInfo) error {
	clientReader := bufio.NewReader(client)
	remoteReader := bufio.NewReader(remote)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Set idle timeout between requests to prevent connection hogging.
		if err := client.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return fmt.Errorf("set idle deadline: %w", err)
		}
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("read HTTP request: %w", err)
		}
		if err := client.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clear read deadline: %w", err)
		}

		// Re-evaluate rules based on Host header if SNI was empty
		host := hostFromRequest(req, sni)

		// Domain fronting: Host header doesn't match TLS SNI
		if isDomainFronting(req, sni) {
			p.log.Debugf("domain fronting detected: SNI=%s Host=%s", sni.PunycodeString(), host.PunycodeString())
			writeBlockResponse(client, req, host)
			return ErrBlocked
		}

		proto := ProtoHTTP
		if isWebSocketUpgrade(req) {
			proto = ProtoWebSocket
		}
		action := p.evaluateAction(src.IP, host, dst, proto, req.URL.Path)
		if action == ActionBlock {
			p.log.Debugf("block: HTTP %s %s (host=%s)", req.Method, req.URL.Path, host.PunycodeString())
			writeBlockResponse(client, req, host)
			return ErrBlocked
		}
		p.log.Tracef("allow: HTTP %s %s (host=%s, action=%s)", req.Method, req.URL.Path, host.PunycodeString(), action)

		// ICAP REQMOD: send request for inspection.
		// Snapshot ICAP client under lock to avoid use-after-close races.
		p.mu.RLock()
		icap := p.icap
		p.mu.RUnlock()
		if icap != nil {
			modified, err := icap.ReqMod(req)
			if err != nil {
				p.log.Debugf("ICAP REQMOD error for %s: %v", host.PunycodeString(), err)
				// Fail-closed: block on ICAP error
				writeBlockResponse(client, req, host)
				return fmt.Errorf("ICAP REQMOD: %w", err)
			}
			req = modified
		}

		if isWebSocketUpgrade(req) {
			return p.handleWebSocket(ctx, req, client, clientReader, remote, remoteReader)
		}

		removeHopByHopHeaders(req.Header)

		if err := req.Write(remote); err != nil {
			return fmt.Errorf("forward request: %w", err)
		}

		resp, err := http.ReadResponse(remoteReader, req)
		if err != nil {
			return fmt.Errorf("read HTTP response: %w", err)
		}

		// ICAP RESPMOD: send response for inspection
		if icap != nil {
			modified, err := icap.RespMod(req, resp)
			if err != nil {
				p.log.Debugf("ICAP RESPMOD error for %s: %v", host.PunycodeString(), err)
				if err := resp.Body.Close(); err != nil {
					p.log.Debugf("close resp body: %v", err)
				}
				writeBlockResponse(client, req, host)
				return fmt.Errorf("ICAP RESPMOD: %w", err)
			}
			resp = modified
		}

		removeHopByHopHeaders(resp.Header)

		if err := resp.Write(client); err != nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				p.log.Debugf("close resp body: %v", closeErr)
			}
			return fmt.Errorf("forward response: %w", err)
		}
		if err := resp.Body.Close(); err != nil {
			p.log.Debugf("close resp body: %v", err)
		}

		// Connection: close means we're done
		if resp.Close || req.Close {
			return nil
		}
	}
}

// inspectH2 proxies HTTP/2 traffic using Go's http stack.
// Client and remote are already-established TLS connections with h2 negotiated.
func (p *Proxy) inspectH2(ctx context.Context, client, remote net.Conn, dst netip.AddrPort, sni domain.Domain, src SourceInfo) error {
	// For h2 MITM inspection, we use a local http.Server reading from the client
	// connection and an http.Transport writing to the remote connection.
	//
	// The transport is configured to use the existing TLS connection to the
	// real server. The handler inspects each request/response pair.

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return remote, nil
		},
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return remote, nil
		},
		ForceAttemptHTTP2: true,
	}

	handler := &h2InspectionHandler{
		proxy:     p,
		transport: transport,
		dst:       dst,
		sni:       sni,
		src:       src,
	}

	server := &http.Server{
		Handler: handler,
	}

	// Serve the single client connection.
	// ServeConn blocks until the connection is done.
	errCh := make(chan error, 1)
	go func() {
		// http.Server doesn't have a direct ServeConn for h2,
		// so we use Serve with a single-connection listener.
		ln := &singleConnListener{conn: client}
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		if err := server.Close(); err != nil {
			p.log.Debugf("close h2 server: %v", err)
		}
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// h2InspectionHandler inspects each HTTP/2 request/response pair.
type h2InspectionHandler struct {
	proxy     *Proxy
	transport http.RoundTripper
	dst       netip.AddrPort
	sni       domain.Domain
	src       SourceInfo
}

func (h *h2InspectionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := hostFromRequest(req, h.sni)

	if isDomainFronting(req, h.sni) {
		h.proxy.log.Debugf("domain fronting detected: SNI=%s Host=%s", h.sni.PunycodeString(), host.PunycodeString())
		writeBlockPage(w, host)
		return
	}

	action := h.proxy.evaluateAction(h.src.IP, host, h.dst, ProtoH2, req.URL.Path)
	if action == ActionBlock {
		h.proxy.log.Debugf("block: H2 %s %s (host=%s)", req.Method, req.URL.Path, host.PunycodeString())
		writeBlockPage(w, host)
		return
	}

	// ICAP REQMOD
	if h.proxy.icap != nil {
		modified, err := h.proxy.icap.ReqMod(req)
		if err != nil {
			h.proxy.log.Debugf("ICAP REQMOD error for %s: %v", host.PunycodeString(), err)
			writeBlockPage(w, host)
			return
		}
		req = modified
	}

	// Forward to upstream
	req.URL.Scheme = "https"
	req.URL.Host = h.sni.PunycodeString()
	req.RequestURI = ""

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		h.proxy.log.Debugf("h2 upstream error for %s: %v", host.PunycodeString(), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			h.proxy.log.Debugf("close h2 resp body: %v", err)
		}
	}()

	// ICAP RESPMOD
	if h.proxy.icap != nil {
		modified, err := h.proxy.icap.RespMod(req, resp)
		if err != nil {
			h.proxy.log.Debugf("ICAP RESPMOD error for %s: %v", host.PunycodeString(), err)
			writeBlockPage(w, host)
			return
		}
		resp = modified
	}

	// Copy response headers and body
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.proxy.log.Debugf("h2 response copy error: %v", err)
	}
}

// handleWebSocket completes the WebSocket upgrade and relays frames bidirectionally.
func (p *Proxy) handleWebSocket(ctx context.Context, req *http.Request, client io.ReadWriter, clientReader *bufio.Reader, remote io.ReadWriter, remoteReader *bufio.Reader) error {
	if err := req.Write(remote); err != nil {
		return fmt.Errorf("forward WebSocket upgrade: %w", err)
	}

	resp, err := http.ReadResponse(remoteReader, req)
	if err != nil {
		return fmt.Errorf("read WebSocket upgrade response: %w", err)
	}

	if err := resp.Write(client); err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.log.Debugf("close ws resp body: %v", closeErr)
		}
		return fmt.Errorf("forward WebSocket upgrade response: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		p.log.Debugf("close ws resp body: %v", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("WebSocket upgrade rejected: status %d", resp.StatusCode)
	}

	p.log.Tracef("allow: WebSocket upgrade for %s", req.Host)

	// Relay WebSocket frames bidirectionally.
	// clientReader/remoteReader may have buffered data.
	clientConn := mergeReadWriter(clientReader, client)
	remoteConn := mergeReadWriter(remoteReader, remote)

	return relayRW(ctx, clientConn, remoteConn)
}

// hostFromRequest extracts a domain.Domain from the HTTP request Host header,
// falling back to the SNI if Host is empty or an IP.
func hostFromRequest(req *http.Request, fallback domain.Domain) domain.Domain {
	host := req.Host
	if host == "" {
		return fallback
	}

	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// If it's an IP address, use the SNI fallback
	if _, err := netip.ParseAddr(host); err == nil {
		return fallback
	}

	d, err := domain.FromString(host)
	if err != nil {
		return fallback
	}
	return d
}

// isDomainFronting detects domain fronting: the Host header doesn't match the
// SNI used during the TLS handshake. Only meaningful when SNI is non-empty
// (i.e., we're in MITM mode and know the original SNI).
func isDomainFronting(req *http.Request, sni domain.Domain) bool {
	if sni == "" {
		return false
	}

	host := hostFromRequest(req, "")
	if host == "" {
		return false
	}

	// Host should match SNI or be a subdomain of SNI
	if host == sni {
		return false
	}

	// Allow www.example.com when SNI is example.com
	sniStr := sni.PunycodeString()
	hostStr := host.PunycodeString()
	if strings.HasSuffix(hostStr, "."+sniStr) {
		return false
	}

	return true
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get(headerUpgrade), valueWebSocket)
}

// writeBlockPage writes the styled HTML block page to an http.ResponseWriter (H2 path).
func writeBlockPage(w http.ResponseWriter, host domain.Domain) {
	hostname := host.PunycodeString()
	body := fmt.Sprintf(blockPageHTML, hostname, hostname)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, body)
}

func writeBlockResponse(w io.Writer, _ *http.Request, host domain.Domain) {
	hostname := host.PunycodeString()
	body := fmt.Sprintf(blockPageHTML, hostname, hostname)

	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Connection", "close")
	resp.Header.Set("Cache-Control", "no-store")
	_ = resp.Write(w)
}

// blockPageHTML is the self-contained HTML block page.
// Uses NetBird dark theme with orange accent. Two format args: page title domain, displayed domain.
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked - %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#181a1d;color:#d1d5db;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.c{text-align:center;max-width:460px;padding:2rem}
.shield{width:56px;height:56px;margin:0 auto 1.5rem;border-radius:16px;background:#2b2f33;display:flex;align-items:center;justify-content:center}
.shield svg{width:28px;height:28px;color:#f68330}
.code{font-size:.8rem;font-weight:500;color:#f68330;font-family:ui-monospace,monospace;letter-spacing:.05em;margin-bottom:.5rem}
h1{font-size:1.5rem;font-weight:600;color:#f4f4f5;margin-bottom:.5rem}
p{font-size:.95rem;line-height:1.5;color:#9ca3af;margin-bottom:1.75rem}
.domain{display:inline-block;background:#25282d;border:1px solid #32363d;border-radius:6px;padding:.15rem .5rem;font-family:ui-monospace,monospace;font-size:.85rem;color:#d1d5db}
.footer{font-size:.7rem;color:#6b7280;margin-top:2rem;letter-spacing:.03em}
.footer a{color:#6b7280;text-decoration:none}
.footer a:hover{color:#9ca3af}
</style>
</head>
<body>
<div class="c">
<div class="shield"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751A11.96 11.96 0 0 0 12 3.714Z"/></svg></div>
<div class="code">403 BLOCKED</div>
<h1>Access Denied</h1>
<p>This connection to <span class="domain">%s</span> has been blocked by your organization's network policy.</p>
<div class="footer">Protected by <a href="https://netbird.io" target="_blank" rel="noopener">NetBird</a></div>
</div>
</body>
</html>`

// singleConnListener is a net.Listener that yields a single connection.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	ch   chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted bool
	l.once.Do(func() {
		l.ch = make(chan struct{})
		accepted = true
	})
	if accepted {
		return l.conn, nil
	}
	// Block until Close
	<-l.ch
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {
		l.ch = make(chan struct{})
	})
	select {
	case <-l.ch:
	default:
		close(l.ch)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type readWriter struct {
	io.Reader
	io.Writer
}

func mergeReadWriter(r io.Reader, w io.Writer) io.ReadWriter {
	return &readWriter{Reader: r, Writer: w}
}

// relayRW copies data bidirectionally between two ReadWriters.
func relayRW(ctx context.Context, a, b io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(b, a)
		cancel()
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(a, b)
		cancel()
		errCh <- err
	}()

	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			if !isClosedErr(err) {
				firstErr = err
			}
		}
	}

	return firstErr
}

// hopByHopHeaders are HTTP/1.1 headers that apply to a single connection
// and must not be forwarded by a proxy (RFC 7230, Section 6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders strips hop-by-hop headers from h.
// Also removes headers listed in the Connection header value.
func removeHopByHopHeaders(h http.Header) {
	// First, remove any headers named in the Connection header
	for _, connHeader := range h["Connection"] {
		for _, name := range strings.Split(connHeader, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}

	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}
