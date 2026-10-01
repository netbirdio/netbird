package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// dialTimeout bounds connection establishment only. Request and response
	// bodies stream without a deadline so long downloads are not cut off.
	dialTimeout = 30 * time.Second

	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = time.Second
	maxIdleConns          = 100
)

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

// newHTTPForwarder binds the local listener and prepares the reverse proxy.
// Binding happens here rather than in Serve so a port clash is reported before
// any forward is announced as ready.
func newHTTPForwarder(fwd Forward, dial DialFunc) (*httpForwarder, error) {
	listener, err := net.Listen("tcp", fwd.Listen)
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
			http.Error(w, "upstream unreachable over the overlay", http.StatusBadGateway)
		},
	}

	return &httpForwarder{
		forward:  fwd,
		listener: listener,
		server:   &http.Server{Handler: proxy},
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
func (f *httpForwarder) Close(ctx context.Context) error {
	return f.server.Shutdown(ctx)
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
