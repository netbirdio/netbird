package tcp

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// defaultDialTimeout is the fallback dial timeout when no per-route
// timeout is configured.
const defaultDialTimeout = 30 * time.Second

// sniHost is a typed key for SNI hostname lookups.
type sniHost = string

// serviceID is a typed key for per-service context tracking.
type serviceID = string

// RouteType specifies how a connection should be handled.
type RouteType int

const (
	// RouteHTTP routes the connection through the HTTP reverse proxy.
	RouteHTTP RouteType = iota
	// RouteTCP relays the connection directly to the backend (TLS passthrough).
	RouteTCP
)

const (
	// sniPeekTimeout is the deadline for reading the TLS ClientHello.
	sniPeekTimeout = 5 * time.Second
	// DefaultDrainTimeout is the default grace period for in-flight relay
	// connections to finish during shutdown.
	DefaultDrainTimeout = 30 * time.Second
	// DefaultMaxRelayConns is the default cap on concurrent TCP relay connections per router.
	DefaultMaxRelayConns = 4096
	// httpChannelBuffer is the capacity of the channel feeding HTTP connections.
	httpChannelBuffer = 4096
)

// DialResolver returns a DialContextFunc for the given account.
type DialResolver func(accountID types.AccountID) (types.DialContextFunc, error)

// Route describes where a connection for a given SNI should be sent.
type Route struct {
	Type      RouteType
	AccountID types.AccountID
	ServiceID string
	// Target is the backend address for TCP relay (e.g. "10.0.0.5:5432").
	Target string
	// ProxyProtocol enables sending a PROXY protocol v2 header to the backend.
	ProxyProtocol bool
	// DialTimeout overrides the default dial timeout for this route.
	// Zero uses defaultDialTimeout.
	DialTimeout time.Duration
}

// RelayObserver receives callbacks for TCP relay lifecycle events.
// All methods must be safe for concurrent use.
type RelayObserver interface {
	TCPRelayStarted(accountID string)
	TCPRelayEnded(accountID string, duration time.Duration, srcToDst, dstToSrc int64)
	TCPRelayDialError(accountID string)
	TCPRelayRejected(accountID string)
}

// Router accepts raw TCP connections on a shared listener, peeks at
// the TLS ClientHello to extract the SNI, and routes the connection
// to either the HTTP reverse proxy or a direct TCP relay.
type Router struct {
	logger *log.Logger
	// httpCh is immutable after construction: set only in NewRouter, nil in NewPortRouter.
	httpCh       chan net.Conn
	httpListener *chanListener
	mu           sync.RWMutex
	routes       map[sniHost][]Route
	fallback     *Route
	draining     bool
	dialResolve  DialResolver
	activeRelays sync.WaitGroup
	relaySem     chan struct{}
	drainDone    chan struct{}
	observer     RelayObserver
	// svcCtxs tracks a context per service ID. All relay goroutines for a
	// service derive from its context; canceling it kills them immediately.
	svcCtxs    map[serviceID]context.Context
	svcCancels map[serviceID]context.CancelFunc
}

// NewRouter creates a new SNI-based connection router.
func NewRouter(logger *log.Logger, dialResolve DialResolver, addr net.Addr) *Router {
	httpCh := make(chan net.Conn, httpChannelBuffer)
	return &Router{
		logger:       logger,
		httpCh:       httpCh,
		httpListener: newChanListener(httpCh, addr),
		routes:       make(map[sniHost][]Route),
		dialResolve:  dialResolve,
		relaySem:     make(chan struct{}, DefaultMaxRelayConns),
		svcCtxs:      make(map[serviceID]context.Context),
		svcCancels:   make(map[serviceID]context.CancelFunc),
	}
}

// NewPortRouter creates a Router for a dedicated port without an HTTP
// channel. Connections that don't match any SNI route fall through to
// the fallback relay (if set) or are closed.
func NewPortRouter(logger *log.Logger, dialResolve DialResolver) *Router {
	return &Router{
		logger:      logger,
		routes:      make(map[sniHost][]Route),
		dialResolve: dialResolve,
		relaySem:    make(chan struct{}, DefaultMaxRelayConns),
		svcCtxs:     make(map[serviceID]context.Context),
		svcCancels:  make(map[serviceID]context.CancelFunc),
	}
}

// HTTPListener returns a net.Listener that yields connections routed
// to the HTTP handler. Use this with http.Server.ServeTLS.
func (r *Router) HTTPListener() net.Listener {
	return r.httpListener
}

// AddRoute registers an SNI route. Multiple routes for the same host are
// stored and resolved by priority at lookup time (HTTP > TCP).
// Empty host is ignored to prevent conflicts with ECH/ESNI fallback.
func (r *Router) AddRoute(host string, route Route) {
	if host == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	routes := r.routes[host]
	for i, existing := range routes {
		if existing.ServiceID == route.ServiceID {
			r.cancelServiceLocked(route.ServiceID)
			routes[i] = route
			return
		}
	}
	r.routes[host] = append(routes, route)
}

// RemoveRoute removes the route for the given host and service ID.
// Active relay connections for the service are closed immediately.
// If other routes remain for the host, they are preserved.
func (r *Router) RemoveRoute(host, serviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes[host] = slices.DeleteFunc(r.routes[host], func(route Route) bool {
		return route.ServiceID == serviceID
	})
	if len(r.routes[host]) == 0 {
		delete(r.routes, host)
	}
	r.cancelServiceLocked(serviceID)
}

// SetFallback registers a catch-all route for connections that don't
// match any SNI route. On a port router this handles plain TCP relay;
// on the main router it takes priority over the HTTP channel.
func (r *Router) SetFallback(route Route) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = &route
}

// RemoveFallback clears the catch-all fallback route and closes any
// active relay connections for the given service.
func (r *Router) RemoveFallback(serviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = nil
	r.cancelServiceLocked(serviceID)
}

// SetObserver sets the relay lifecycle observer. Must be called before Serve.
func (r *Router) SetObserver(obs RelayObserver) {
	r.observer = obs
}

// IsEmpty returns true when the router has no SNI routes and no fallback.
func (r *Router) IsEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes) == 0 && r.fallback == nil
}

// Serve accepts connections from ln and routes them based on SNI.
// It blocks until ctx is canceled or ln is closed, then drains
// active relay connections up to DefaultDrainTimeout.
func (r *Router) Serve(ctx context.Context, ln net.Listener) error {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			if r.httpListener != nil {
				r.httpListener.Close()
			}
		case <-done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				if ok := r.Drain(DefaultDrainTimeout); !ok {
					r.logger.Warn("timed out waiting for relay connections to drain")
				}
				return nil
			}
			r.logger.Debugf("SNI router accept: %v", err)
			continue
		}
		go r.handleConn(ctx, conn)
	}
}

// handleConn peeks at the TLS ClientHello and routes the connection.
func (r *Router) handleConn(ctx context.Context, conn net.Conn) {
	// Fast path: when no SNI routes and no HTTP channel exist (pure TCP
	// fallback port), skip the TLS peek entirely to avoid read errors on
	// non-TLS connections and reduce latency.
	if r.isFallbackOnly() {
		r.handleUnmatched(ctx, conn)
		return
	}

	if err := conn.SetReadDeadline(time.Now().Add(sniPeekTimeout)); err != nil {
		r.logger.Debugf("set SNI peek deadline: %v", err)
		_ = conn.Close()
		return
	}

	sni, wrapped, err := PeekClientHello(conn)
	if err != nil {
		r.logger.Debugf("SNI peek: %v", err)
		if wrapped != nil {
			r.handleUnmatched(ctx, wrapped)
		} else {
			_ = conn.Close()
		}
		return
	}

	if err := wrapped.SetReadDeadline(time.Time{}); err != nil {
		r.logger.Debugf("clear SNI peek deadline: %v", err)
		_ = wrapped.Close()
		return
	}

	route, ok := r.lookupRoute(sni)
	if !ok {
		r.handleUnmatched(ctx, wrapped)
		return
	}

	if route.Type == RouteHTTP {
		r.sendToHTTP(wrapped)
		return
	}

	r.relayTCP(ctx, wrapped, sni, route)
}

// isFallbackOnly returns true when the router has no SNI routes and no HTTP
// channel, meaning all connections should go directly to the fallback relay.
func (r *Router) isFallbackOnly() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes) == 0 && r.httpCh == nil
}

// handleUnmatched routes a connection that didn't match any SNI route.
// This includes ECH/ESNI connections where the cleartext SNI is empty.
// It tries the fallback relay first, then the HTTP channel, and closes
// the connection if neither is available.
func (r *Router) handleUnmatched(ctx context.Context, conn net.Conn) {
	r.mu.RLock()
	fb := r.fallback
	r.mu.RUnlock()

	if fb != nil {
		r.relayTCP(ctx, conn, "fallback", *fb)
		return
	}
	r.sendToHTTP(conn)
}

// lookupRoute returns the highest-priority route for the given SNI host.
// HTTP routes take precedence over TCP routes.
func (r *Router) lookupRoute(sni string) (Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	routes, ok := r.routes[sni]
	if !ok || len(routes) == 0 {
		return Route{}, false
	}
	best := routes[0]
	for _, route := range routes[1:] {
		if route.Type < best.Type {
			best = route
		}
	}
	return best, true
}

// sendToHTTP feeds the connection to the HTTP handler via the channel.
// If no HTTP channel is configured (port router), the router is
// draining, or the channel is full, the connection is closed.
func (r *Router) sendToHTTP(conn net.Conn) {
	if r.httpCh == nil {
		_ = conn.Close()
		return
	}

	r.mu.RLock()
	draining := r.draining
	r.mu.RUnlock()

	if draining {
		_ = conn.Close()
		return
	}

	select {
	case r.httpCh <- conn:
	default:
		r.logger.Warnf("HTTP channel full, dropping connection from %s", conn.RemoteAddr())
		_ = conn.Close()
	}
}

// Drain prevents new relay connections from starting and waits for all
// active relays to finish, up to the given timeout. Returns true if all
// relays completed, false on timeout.
func (r *Router) Drain(timeout time.Duration) bool {
	r.mu.Lock()
	r.draining = true
	if r.drainDone == nil {
		done := make(chan struct{})
		go func() {
			r.activeRelays.Wait()
			close(done)
		}()
		r.drainDone = done
	}
	done := r.drainDone
	r.mu.Unlock()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// cancelServiceLocked cancels and removes the context for the given service,
// closing all its active relay connections. Must be called with mu held.
func (r *Router) cancelServiceLocked(serviceID string) {
	if cancel, ok := r.svcCancels[serviceID]; ok {
		cancel()
		delete(r.svcCtxs, serviceID)
		delete(r.svcCancels, serviceID)
	}
}

// relayTCP dials the backend and starts a bidirectional relay.
// The relay uses a per-service context: when the service is removed
// via RemoveRoute/RemoveFallback, all its relays are killed immediately.
func (r *Router) relayTCP(ctx context.Context, conn net.Conn, sni string, route Route) {
	r.mu.Lock()
	if r.draining {
		r.mu.Unlock()
		_ = conn.Close()
		return
	}
	r.activeRelays.Add(1)
	svcCtx := r.getOrCreateServiceCtxLocked(ctx, route.ServiceID)
	r.mu.Unlock()

	select {
	case r.relaySem <- struct{}{}:
	default:
		r.activeRelays.Done()
		r.logger.Warn("TCP relay connection limit reached, rejecting connection")
		if r.observer != nil {
			r.observer.TCPRelayRejected(string(route.AccountID))
		}
		_ = conn.Close()
		return
	}
	defer func() {
		<-r.relaySem
		r.activeRelays.Done()
	}()

	acct := string(route.AccountID)
	entry := r.logger.WithFields(log.Fields{
		"sni":        sni,
		"service_id": route.ServiceID,
		"target":     route.Target,
	})

	dialFn, err := r.dialResolve(route.AccountID)
	if err != nil {
		entry.Warnf("failed to resolve dialer: %v", err)
		_ = conn.Close()
		return
	}

	dialTimeout := route.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	dialCtx, dialCancel := context.WithTimeout(svcCtx, dialTimeout)
	backend, err := dialFn(dialCtx, "tcp", route.Target)
	dialCancel()
	if err != nil {
		entry.Warnf("failed to dial backend: %v", err)
		if r.observer != nil {
			r.observer.TCPRelayDialError(acct)
		}
		_ = conn.Close()
		return
	}

	if route.ProxyProtocol {
		if err := writeProxyProtoV2(conn, backend); err != nil {
			entry.Warnf("failed to write PROXY protocol header: %v", err)
			_ = conn.Close()
			_ = backend.Close()
			return
		}
	}

	if r.observer != nil {
		r.observer.TCPRelayStarted(acct)
	}
	entry.Debug("TCP relay started")
	start := time.Now()
	s2d, d2s := Relay(svcCtx, entry, conn, backend, DefaultIdleTimeout)
	elapsed := time.Since(start)
	if r.observer != nil {
		r.observer.TCPRelayEnded(acct, elapsed, s2d, d2s)
	}
	entry.Debugf("TCP relay ended (client→backend: %d bytes, backend→client: %d bytes)", s2d, d2s)
}

// getOrCreateServiceCtxLocked returns the context for a service, creating one
// if it doesn't exist yet. The context is a child of the server context.
// Must be called with mu held.
func (r *Router) getOrCreateServiceCtxLocked(parent context.Context, serviceID string) context.Context {
	if ctx, ok := r.svcCtxs[serviceID]; ok {
		return ctx
	}
	ctx, cancel := context.WithCancel(parent)
	r.svcCtxs[serviceID] = ctx
	r.svcCancels[serviceID] = cancel
	return ctx
}
