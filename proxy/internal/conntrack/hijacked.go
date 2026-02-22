package conntrack

import (
	"net/http"
	"sync"
)

// HijackTracker tracks connections that have been hijacked (e.g. WebSocket
// upgrades). http.Server.Shutdown does not close hijacked connections, so
// they must be tracked and closed explicitly during graceful shutdown.
//
// Connections are indexed by the request Host so they can be closed
// per-domain when a service mapping is removed.
//
// Use Middleware as the outermost HTTP middleware to ensure hijacked
// connections are tracked and automatically deregistered when closed.
type HijackTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

// Middleware returns an HTTP middleware that wraps the ResponseWriter so that
// hijacked connections are tracked and automatically deregistered from the
// tracker when closed. This should be the outermost middleware in the chain.
func (t *HijackTracker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&trackingWriter{
			ResponseWriter: w,
			tracker:        t,
			host:           hostOnly(r.Host),
		}, r)
	})
}

// CloseAll closes all tracked hijacked connections and returns the count.
func (t *HijackTracker) CloseAll() int {
	t.mu.Lock()
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()

	for tc := range conns {
		_ = tc.Conn.Close()
	}
	return len(conns)
}

// CloseByHost closes all tracked hijacked connections for the given host
// and returns the number of connections closed.
func (t *HijackTracker) CloseByHost(host string) int {
	t.mu.Lock()
	var toClose []*trackedConn
	for tc := range t.conns {
		if tc.host == host {
			toClose = append(toClose, tc)
		}
	}
	for _, tc := range toClose {
		delete(t.conns, tc)
	}
	t.mu.Unlock()

	for _, tc := range toClose {
		_ = tc.Conn.Close()
	}
	return len(toClose)
}

func (t *HijackTracker) add(tc *trackedConn) {
	t.mu.Lock()
	if t.conns == nil {
		t.conns = make(map[*trackedConn]struct{})
	}
	t.conns[tc] = struct{}{}
	t.mu.Unlock()
}

func (t *HijackTracker) remove(tc *trackedConn) {
	t.mu.Lock()
	delete(t.conns, tc)
	t.mu.Unlock()
}

// hostOnly strips the port from a host:port string.
func hostOnly(hostport string) string {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i]
		}
		if hostport[i] < '0' || hostport[i] > '9' {
			return hostport
		}
	}
	return hostport
}
