package conntrack

import (
	"net"
	"net/http"
	"sync"
)

// HijackTracker tracks connections that have been hijacked (e.g. WebSocket
// upgrades). http.Server.Shutdown does not close hijacked connections, so
// they must be tracked and closed explicitly during graceful shutdown.
//
// Use Middleware as the outermost HTTP middleware to ensure hijacked
// connections are tracked and automatically deregistered when closed.
type HijackTracker struct {
	conns sync.Map // net.Conn → struct{}
}

// Middleware returns an HTTP middleware that wraps the ResponseWriter so that
// hijacked connections are tracked and automatically deregistered from the
// tracker when closed. This should be the outermost middleware in the chain.
func (t *HijackTracker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&trackingWriter{ResponseWriter: w, tracker: t}, r)
	})
}

// CloseAll closes all tracked hijacked connections and returns the number
// of connections that were closed.
func (t *HijackTracker) CloseAll() int {
	var count int
	t.conns.Range(func(key, _ any) bool {
		if conn, ok := key.(net.Conn); ok {
			_ = conn.Close()
			count++
		}
		t.conns.Delete(key)
		return true
	})
	return count
}
