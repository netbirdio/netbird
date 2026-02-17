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
// Use ConnState as the http.Server.ConnState callback.
type HijackTracker struct {
	conns sync.Map // net.Conn → struct{}
}

// ConnState is an http.Server.ConnState callback that records connections
// entering the hijacked state and removes them when closed.
func (t *HijackTracker) ConnState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateHijacked:
		t.conns.Store(conn, struct{}{})
	case http.StateClosed:
		t.conns.Delete(conn)
	default:
	}
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
