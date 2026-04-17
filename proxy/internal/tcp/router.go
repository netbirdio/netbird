package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// defaultDialTimeout is the fallback dial timeout when no per-route
// timeout is configured.
const defaultDialTimeout = 30 * time.Second

// errAccessRestricted is returned by relayTCP for access restriction
// denials so callers can skip warn-level logging (already logged at debug).
var errAccessRestricted = errors.New("rejected by access restrictions")

// SNIHost is a typed key for SNI hostname lookups.
type SNIHost string

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
	ServiceID types.ServiceID
	// Domain is the service's configured domain, used for access log entries.
	Domain string
	// Protocol is the frontend protocol (tcp, tls), used for access log entries.
	Protocol accesslog.Protocol
	// Target is the backend address for TCP relay (e.g. "10.0.0.5:5432").
	Target string
	// ProxyProtocol enables sending a PROXY protocol v2 header to the backend.
	ProxyProtocol bool
	// DialTimeout overrides the default dial timeout for this route.
	// Zero uses defaultDialTimeout.
	DialTimeout time.Duration
	// SessionIdleTimeout overrides the default idle timeout for relay connections.
	// Zero uses DefaultIdleTimeout.
	SessionIdleTimeout time.Duration
	// Filter holds connection-level IP/geo restrictions. Nil means no restrictions.
	Filter *restrict.Filter
}

// l4Logger sends layer-4 access log entries to the management server.
type l4Logger interface {
	LogL4(entry accesslog.L4Entry)
}

// RelayObserver receives callbacks for TCP relay lifecycle events.
// All methods must be safe for concurrent use.
type RelayObserver interface {
	TCPRelayStarted(accountID types.AccountID)
	TCPRelayEnded(accountID types.AccountID, duration time.Duration, srcToDst, dstToSrc int64)
	TCPRelayDialError(accountID types.AccountID)
	TCPRelayRejected(accountID types.AccountID)
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
	routes       map[SNIHost][]Route
	fallback     *Route
	draining     bool
	dialResolve  DialResolver
	activeConns  sync.WaitGroup
	activeRelays sync.WaitGroup
	relaySem     chan struct{}
	drainDone    chan struct{}
	observer     RelayObserver
	accessLog    l4Logger
	geo          restrict.GeoResolver
	// svcCtxs tracks a context per service ID. All relay goroutines for a
	// service derive from its context; canceling it kills them immediately.
	svcCtxs    map[types.ServiceID]context.Context
	svcCancels map[types.ServiceID]context.CancelFunc
}

// NewRouter creates a new SNI-based connection router.
func NewRouter(logger *log.Logger, dialResolve DialResolver, addr net.Addr) *Router {
	httpCh := make(chan net.Conn, httpChannelBuffer)
	return &Router{
		logger:       logger,
		httpCh:       httpCh,
		httpListener: newChanListener(httpCh, addr),
		routes:       make(map[SNIHost][]Route),
		dialResolve:  dialResolve,
		relaySem:     make(chan struct{}, DefaultMaxRelayConns),
		svcCtxs:      make(map[types.ServiceID]context.Context),
		svcCancels:   make(map[types.ServiceID]context.CancelFunc),
	}
}

// NewPortRouter creates a Router for a dedicated port without an HTTP
// channel. Connections that don't match any SNI route fall through to
// the fallback relay (if set) or are closed.
func NewPortRouter(logger *log.Logger, dialResolve DialResolver) *Router {
	return &Router{
		logger:      logger,
		routes:      make(map[SNIHost][]Route),
		dialResolve: dialResolve,
		relaySem:    make(chan struct{}, DefaultMaxRelayConns),
		svcCtxs:     make(map[types.ServiceID]context.Context),
		svcCancels:  make(map[types.ServiceID]context.CancelFunc),
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
func (r *Router) AddRoute(host SNIHost, route Route) {
	host = SNIHost(strings.ToLower(string(host)))
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
func (r *Router) RemoveRoute(host SNIHost, svcID types.ServiceID) {
	host = SNIHost(strings.ToLower(string(host)))

	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes[host] = slices.DeleteFunc(r.routes[host], func(route Route) bool {
		return route.ServiceID == svcID
	})
	if len(r.routes[host]) == 0 {
		delete(r.routes, host)
	}
	r.cancelServiceLocked(svcID)
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
func (r *Router) RemoveFallback(svcID types.ServiceID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = nil
	r.cancelServiceLocked(svcID)
}

// SetObserver sets the relay lifecycle observer. Must be called before Serve.
func (r *Router) SetObserver(obs RelayObserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observer = obs
}

// SetAccessLogger sets the L4 access logger. Must be called before Serve.
func (r *Router) SetAccessLogger(l l4Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accessLog = l
}

// getObserver returns the current relay observer under the read lock.
func (r *Router) getObserver() RelayObserver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.observer
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
					r.logger.Warn("timed out waiting for connections to drain")
				}
				return nil
			}
			r.logger.Debugf("SNI router accept: %v", err)
			continue
		}
		r.activeConns.Add(1)
		go func() {
			defer r.activeConns.Done()
			r.handleConn(ctx, conn)
		}()
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

	host := SNIHost(strings.ToLower(sni))
	route, ok := r.lookupRoute(host)
	if !ok {
		r.handleUnmatched(ctx, wrapped)
		return
	}

	if route.Type == RouteHTTP {
		r.sendToHTTP(wrapped)
		return
	}

	if err := r.relayTCP(ctx, wrapped, host, route); err != nil {
		if !errors.Is(err, errAccessRestricted) {
			r.logger.WithFields(log.Fields{
				"sni":        host,
				"service_id": route.ServiceID,
				"target":     route.Target,
			}).Warnf("TCP relay: %v", err)
		}
		_ = wrapped.Close()
	}
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
		if err := r.relayTCP(ctx, conn, SNIHost("fallback"), *fb); err != nil {
			if !errors.Is(err, errAccessRestricted) {
				r.logger.WithFields(log.Fields{
					"service_id": fb.ServiceID,
					"target":     fb.Target,
				}).Warnf("TCP relay (fallback): %v", err)
			}
			_ = conn.Close()
		}
		return
	}
	r.sendToHTTP(conn)
}

// lookupRoute returns the highest-priority route for the given SNI host.
// HTTP routes take precedence over TCP routes.
func (r *Router) lookupRoute(host SNIHost) (Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	routes, ok := r.routes[host]
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
// in-flight connection handlers and active relays to finish, up to the
// given timeout. Returns true if all completed, false on timeout.
func (r *Router) Drain(timeout time.Duration) bool {
	r.mu.Lock()
	r.draining = true
	if r.drainDone == nil {
		done := make(chan struct{})
		go func() {
			r.activeConns.Wait()
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
func (r *Router) cancelServiceLocked(svcID types.ServiceID) {
	if cancel, ok := r.svcCancels[svcID]; ok {
		cancel()
		delete(r.svcCtxs, svcID)
		delete(r.svcCancels, svcID)
	}
}

// SetGeo sets the geolocation lookup used for country-based restrictions.
func (r *Router) SetGeo(geo restrict.GeoResolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.geo = geo
}

// checkRestrictions evaluates the route's access filter against the
// connection's remote address. Returns Allow if the connection is
// permitted, or a deny verdict indicating the reason.
func (r *Router) checkRestrictions(conn net.Conn, route Route) restrict.Verdict {
	if route.Filter == nil {
		return restrict.Allow
	}

	addr, err := addrFromConn(conn)
	if err != nil {
		r.logger.Debugf("cannot parse client address %s for restriction check, denying", conn.RemoteAddr())
		return restrict.DenyCIDR
	}

	r.mu.RLock()
	geo := r.geo
	r.mu.RUnlock()

	return route.Filter.Check(addr, geo)
}

// relayTCP sets up and runs a bidirectional TCP relay.
// The caller owns conn and must close it if this method returns an error.
// On success (nil error), both conn and backend are closed by the relay.
func (r *Router) relayTCP(ctx context.Context, conn net.Conn, sni SNIHost, route Route) error {
	if verdict := r.checkRestrictions(conn, route); verdict != restrict.Allow {
		if route.Filter != nil && route.Filter.IsObserveOnly(verdict) {
			r.logger.Debugf("CrowdSec observe: would block %s for %s (%s)", conn.RemoteAddr(), sni, verdict)
			r.logL4Deny(route, conn, verdict, true)
		} else {
			r.logger.Debugf("connection from %s rejected by access restrictions: %s", conn.RemoteAddr(), verdict)
			r.logL4Deny(route, conn, verdict, false)
			return errAccessRestricted
		}
	}

	svcCtx, err := r.acquireRelay(ctx, route)
	if err != nil {
		return err
	}
	defer func() {
		<-r.relaySem
		r.activeRelays.Done()
	}()

	backend, err := r.dialBackend(svcCtx, route)
	if err != nil {
		obs := r.getObserver()
		if obs != nil {
			obs.TCPRelayDialError(route.AccountID)
		}
		return err
	}

	if route.ProxyProtocol {
		if err := writeProxyProtoV2(conn, backend); err != nil {
			_ = backend.Close()
			return fmt.Errorf("write PROXY protocol header: %w", err)
		}
	}

	obs := r.getObserver()
	if obs != nil {
		obs.TCPRelayStarted(route.AccountID)
	}

	entry := r.logger.WithFields(log.Fields{
		"sni":        sni,
		"service_id": route.ServiceID,
		"target":     route.Target,
	})
	entry.Debug("TCP relay started")

	idleTimeout := route.SessionIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}

	start := time.Now()
	s2d, d2s := Relay(svcCtx, entry, conn, backend, idleTimeout)
	elapsed := time.Since(start)

	if obs != nil {
		obs.TCPRelayEnded(route.AccountID, elapsed, s2d, d2s)
	}
	entry.Debugf("TCP relay ended (client→backend: %d bytes, backend→client: %d bytes)", s2d, d2s)

	r.logL4Entry(route, conn, elapsed, s2d, d2s)
	return nil
}

// acquireRelay checks draining state, increments activeRelays, and acquires
// a semaphore slot. Returns the per-service context on success.
// The caller must release the semaphore and call activeRelays.Done() when done.
func (r *Router) acquireRelay(ctx context.Context, route Route) (context.Context, error) {
	r.mu.Lock()
	if r.draining {
		r.mu.Unlock()
		return nil, errors.New("router is draining")
	}
	r.activeRelays.Add(1)
	svcCtx := r.getOrCreateServiceCtxLocked(ctx, route.ServiceID)
	r.mu.Unlock()

	select {
	case r.relaySem <- struct{}{}:
		return svcCtx, nil
	default:
		r.activeRelays.Done()
		obs := r.getObserver()
		if obs != nil {
			obs.TCPRelayRejected(route.AccountID)
		}
		return nil, errors.New("TCP relay connection limit reached")
	}
}

// dialBackend resolves the dialer for the route's account and dials the backend.
func (r *Router) dialBackend(svcCtx context.Context, route Route) (net.Conn, error) {
	dialFn, err := r.dialResolve(route.AccountID)
	if err != nil {
		return nil, fmt.Errorf("resolve dialer: %w", err)
	}

	dialTimeout := route.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	dialCtx, dialCancel := context.WithTimeout(svcCtx, dialTimeout)
	backend, err := dialFn(dialCtx, "tcp", route.Target)
	dialCancel()
	if err != nil {
		return nil, fmt.Errorf("dial backend %s: %w", route.Target, err)
	}
	return backend, nil
}

// logL4Entry sends a TCP relay access log entry if an access logger is configured.
func (r *Router) logL4Entry(route Route, conn net.Conn, duration time.Duration, bytesUp, bytesDown int64) {
	r.mu.RLock()
	al := r.accessLog
	r.mu.RUnlock()

	if al == nil {
		return
	}

	sourceIP, _ := addrFromConn(conn)

	al.LogL4(accesslog.L4Entry{
		AccountID:     route.AccountID,
		ServiceID:     route.ServiceID,
		Protocol:      route.Protocol,
		Host:          route.Domain,
		SourceIP:      sourceIP,
		DurationMs:    duration.Milliseconds(),
		BytesUpload:   bytesUp,
		BytesDownload: bytesDown,
	})
}

// logL4Deny sends an access log entry for a denied connection.
func (r *Router) logL4Deny(route Route, conn net.Conn, verdict restrict.Verdict, observeOnly bool) {
	r.mu.RLock()
	al := r.accessLog
	r.mu.RUnlock()

	if al == nil {
		return
	}

	sourceIP, _ := addrFromConn(conn)

	entry := accesslog.L4Entry{
		AccountID:  route.AccountID,
		ServiceID:  route.ServiceID,
		Protocol:   route.Protocol,
		Host:       route.Domain,
		SourceIP:   sourceIP,
		DenyReason: verdict.String(),
	}
	if verdict.IsCrowdSec() {
		entry.Metadata = map[string]string{"crowdsec_verdict": verdict.String()}
		if observeOnly {
			entry.Metadata["crowdsec_mode"] = "observe"
			entry.DenyReason = ""
		}
	}
	al.LogL4(entry)
}

// getOrCreateServiceCtxLocked returns the context for a service, creating one
// if it doesn't exist yet. The context is a child of the server context.
// Must be called with mu held.
func (r *Router) getOrCreateServiceCtxLocked(parent context.Context, svcID types.ServiceID) context.Context {
	if ctx, ok := r.svcCtxs[svcID]; ok {
		return ctx
	}
	ctx, cancel := context.WithCancel(parent)
	r.svcCtxs[svcID] = ctx
	r.svcCancels[svcID] = cancel
	return ctx
}

// addrFromConn extracts a netip.Addr from a connection's remote address.
func addrFromConn(conn net.Conn) (netip.Addr, error) {
	remote := conn.RemoteAddr()
	if remote == nil {
		return netip.Addr{}, errors.New("no remote address")
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}
