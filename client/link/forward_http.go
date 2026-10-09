package link

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// dialTimeout bounds connection establishment only. Request and response
	// bodies stream without a deadline so long downloads are not cut off.
	dialTimeout = 30 * time.Second

	// readHeaderTimeout bounds how long a caller may take to send request
	// headers.
	readHeaderTimeout = 10 * time.Second

	// fetchSiteHeader is the browser's own account of how a request was
	// initiated. It is the only one of the three guard signals that a no-cors
	// GET carries.
	fetchSiteHeader = "Sec-Fetch-Site"

	// defaultHTTPPort fills in the port an origin leaves implicit.
	defaultHTTPPort = "80"

	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = time.Second
	maxIdleConns          = 100
)

// bodyIdleTimeout bounds how long a request body may stall without delivering
// more bytes. It is a variable so tests can shorten it.
var bodyIdleTimeout = 30 * time.Second

// foreignFetchSites are the Sec-Fetch-Site values a browser sends when a page
// other than this listener's own initiated the request. A page on another port
// is same-site here, because a bare address or localhost is its own site, yet
// it is a different application with no more claim on this listener than any
// other page has.
var foreignFetchSites = map[string]bool{"cross-site": true, "same-site": true}

// DialFunc establishes a connection inside the overlay. The embedded client
// supplies the real implementation; tests supply their own.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// httpForwarder serves one local HTTP listener and proxies what it accepts to
// an upstream reached over the overlay.
type httpForwarder struct {
	forward  Forward
	server   *http.Server
	listener net.Listener
}

// idleTimeoutBody applies a fresh read deadline before every read, so a
// transfer that keeps progressing runs as long as it needs while a stalled one
// is cut off.
type idleTimeoutBody struct {
	io.ReadCloser
	controller *http.ResponseController
	idle       time.Duration
}

// newHTTPForwarder binds the local listener and prepares the reverse proxy.
// Binding happens here rather than in Serve so a port clash is reported before
// any forward is announced as ready.
func newHTTPForwarder(fwd Forward, dial DialFunc) (*httpForwarder, error) {
	listener, err := net.Listen(listenNetwork(fwd.Listen), fwd.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", fwd.Listen, bindHint(fwd.Listen, err))
	}

	upstream := fwd.Upstream
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			// The upstream decides routing and TLS verification from Host, and
			// it must see its own name rather than the local bind address.
			r.Out.Host = upstream.Host
		},
		Transport: &http.Transport{
			DialContext:           boundedDial(dial),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          maxIdleConns,
			IdleConnTimeout:       idleConnTimeout,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ExpectContinueTimeout: expectContinueTimeout,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Warnf("%s %s %s: %v", fwd.Listen, r.Method, r.URL.Path, err)
			// Nothing read the request body on this path, and the server
			// drains what is left before reusing the connection. Closing it
			// answers the caller now instead of waiting out that drain.
			rejectRequest(w, "upstream unreachable over the overlay", http.StatusBadGateway)
		},
	}

	return &httpForwarder{
		forward:  fwd,
		listener: listener,
		server: &http.Server{
			Handler: withBodyIdleTimeout(guardRebinding(proxy, isLoopback(fwd.Listen), fwd.AllowedHosts)),
			// Bound how long a caller may take to send headers, so a slow
			// sender cannot hold a connection and its goroutine open
			// indefinitely. Neither deadline limits body streaming, so large
			// uploads and downloads still run as long as they need.
			ReadHeaderTimeout: readHeaderTimeout,
			IdleTimeout:       idleConnTimeout,
		},
	}, nil
}

// Addr returns the address actually bound, which differs from the spec when
// the operator asked for port 0.
func (f *httpForwarder) Addr() string {
	return f.listener.Addr().String()
}

// Serve runs until the forwarder is closed.
func (f *httpForwarder) Serve() error {
	if err := f.server.Serve(f.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve %s: %w", f.forward.Listen, err)
	}
	return nil
}

// Close stops the listener and waits for in-flight requests to finish, up to
// the deadline carried by ctx.
//
// Shutdown only closes listeners the server has taken over in Serve, so the
// raw listener is closed here as well. Otherwise a forwarder that was built
// but never served, which happens when a later bind in the same set fails,
// would hold its socket until the process exits.
func (f *httpForwarder) Close(ctx context.Context) error {
	shutdownErr := f.server.Shutdown(ctx)
	if err := f.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return shutdownErr
}

func (b *idleTimeoutBody) Read(p []byte) (int, error) {
	if err := b.setDeadline(time.Now().Add(b.idle)); err != nil {
		return 0, err
	}

	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		// The body arrived in full, so its deadline has to go with it. The
		// server keeps reading the connection while the handler streams its
		// reply, and a deadline left over from the body would cut that reply
		// off partway through.
		//
		// Only EOF clears it. On any other error the caller stalled or the
		// connection broke, and the deadline is what stops the server from
		// blocking forever as it drains what was never sent.
		b.clearDeadline()
	}
	return n, err
}

func (b *idleTimeoutBody) setDeadline(t time.Time) error {
	// A connection that cannot carry a deadline, which the controller reports
	// as unsupported, still reads normally rather than failing the request.
	if err := b.controller.SetReadDeadline(t); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

// clearDeadline removes any read deadline. A failure here cannot be acted on
// and must not mask the error the caller is already returning.
func (b *idleTimeoutBody) clearDeadline() {
	if err := b.setDeadline(time.Time{}); err != nil {
		log.Debugf("clear read deadline: %v", err)
	}
}

// listenNetwork pins the address family to the literal the operator wrote.
// Plain "tcp" turns 0.0.0.0 into a dual-stack wildcard that also accepts IPv6,
// which exposes more than the spec asked for. A "6" network binds IPv6 only.
func listenNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "tcp"
	}
	if ip.Is4() {
		return "tcp4"
	}
	return "tcp6"
}

// boundedDial applies dialTimeout to connection establishment without
// constraining the lifetime of the connection it returns.
func boundedDial(dial DialFunc) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()

		start := time.Now()
		conn, err := dial(ctx, network, addr)
		if err != nil {
			log.Debugf("dial %s over the overlay failed after %s: %v",
				addr, time.Since(start).Truncate(time.Millisecond), err)
			return nil, err
		}
		log.Debugf("dial %s over the overlay took %s, remote %s",
			addr, time.Since(start).Truncate(time.Millisecond), conn.RemoteAddr())
		return conn, nil
	}
}

// bindHint adds the likely cause when a bind fails for a reason an operator
// can act on. The privileged-port boundary is detected from the error rather
// than assumed from the port number, because containers often lower it to zero.
func bindHint(addr string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w (nblink runs unprivileged, so %s likely needs a port above 1023)", err, addr)
	}
	return err
}

// withBodyIdleTimeout cuts off a caller that sends request headers and then
// stops sending the body.
//
// ReadHeaderTimeout covers only the headers, and IdleTimeout applies between
// requests rather than during one, so without this a caller could hold a
// connection and its handler open indefinitely. A total ReadTimeout would
// close that gap but would also break legitimate long uploads, so the deadline
// is refreshed on every read that makes progress instead.
func withBodyIdleTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			b := &idleTimeoutBody{
				ReadCloser: r.Body,
				controller: http.NewResponseController(w),
				idle:       bodyIdleTimeout,
			}
			// Armed before the handler runs rather than on the first read. A
			// handler that never touches the body still leaves the server to
			// drain it afterwards, and that drain reads the connection with
			// whatever deadline is on it: without one it waits forever on a
			// caller that stopped sending.
			if err := b.setDeadline(time.Now().Add(b.idle)); err != nil {
				log.Debugf("arm request body deadline: %v", err)
			}
			r.Body = b
		}
		next.ServeHTTP(w, r)
	})
}

// guardRebinding rejects requests that a browser issued on behalf of some
// other site, and requests that reached a loopback listener under a name that
// is not its own.
//
// A loopback forwarder is reachable from any page the user visits. A site can
// point its own hostname at 127.0.0.1, and it can also embed the loopback
// address directly in an img, script or iframe URL. Either way the browser
// sends the request, and this listener would otherwise proxy it into the
// network under the peer's identity.
//
// Three signals separate those from a local caller. Host carries the
// attacker's name in the rebinding variant. Origin is present on any
// cross-origin fetch. Sec-Fetch-Site covers what the first two miss: the
// browser states how the request was initiated, including on the no-cors GETs
// that carry no Origin at all. Non-browser callers send none of the latter
// two and are unaffected.
//
// A browser too old to send Sec-Fetch-Site can still reach a loopback forward
// with an embedded no-cors GET. Browsers have sent it since 2020, so this
// residual needs a deliberately outdated one.
//
// The Host check holds on a publicly bound listener too, which is how a
// container port published to the host is reached. There a rebound page sends
// its own name with a matching Origin, so Host is the only signal left. Other
// machines reach a public listener by address, which is accepted; any name
// they use instead has to be listed with --allowed-host.
func guardRebinding(next http.Handler, loopbackOnly bool, allowedHosts []string) http.Handler {
	allowed := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[normalizeHostname(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAllowedHost(hostnameOf(r.Host), loopbackOnly, allowed) {
			rejectRequest(w, "unexpected Host for this listener, list it with --allowed-host", http.StatusMisdirectedRequest)
			return
		}
		if !isLocalCaller(r) {
			rejectRequest(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rejectRequest answers a request the forwarder will not proxy and closes the
// connection.
//
// On a keep-alive connection the server drains whatever is left of the request
// body before reading the next request. It drains the original body rather
// than the handler's wrapper, so the idle deadline that bounds an accepted
// upload is never armed for a rejected one, and a caller that stopped sending
// would hold the connection and its goroutine. Closing skips that drain.
func rejectRequest(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Connection", "close")
	http.Error(w, msg, code)
}

// isLocalCaller reports whether a request may be proxied, from what the
// browser says about where it came from.
func isLocalCaller(r *http.Request) bool {
	if foreignFetchSites[strings.ToLower(r.Header.Get(fetchSiteHeader))] {
		return false
	}

	// Only a browser sets Origin, and a legitimate one for this listener is
	// same-origin. Anything else is a cross-site caller.
	origin := r.Header.Get("Origin")
	return origin == "" || isSameOrigin(origin, r.Host)
}

// hostnameOf strips any port from a Host header value.
func hostnameOf(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// isAllowedHost reports whether a request may arrive under host. Loopback
// names always may and listed names always may. A public listener also
// accepts any address, since a page cannot rebind an address it does not
// control.
func isAllowedHost(host string, loopbackOnly bool, allowed map[string]bool) bool {
	if isLocalName(host) || allowed[normalizeHostname(host)] {
		return true
	}
	if loopbackOnly {
		return false
	}
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

// isLocalName reports whether host names this machine's loopback interface.
func isLocalName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

// isSameOrigin reports whether an Origin header names this listener. Scheme,
// host and port all have to match: the forwarder serves plaintext HTTP, and a
// page on another loopback port is a different origin like any other.
func isSameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return normalizeAuthority(u.Host) == normalizeAuthority(host)
}

// normalizeAuthority reduces an authority to a comparable host:port, so two
// spellings of one origin match.
func normalizeAuthority(authority string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host, port = authority, defaultHTTPPort
	}
	return strings.ToLower(strings.Trim(host, "[]")) + ":" + port
}
