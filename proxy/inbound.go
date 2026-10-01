package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/debug"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// httpInboundReadHeaderTimeout matches the host-listener read header timeout
// so per-account http.Servers don't leak idle connections.
const httpInboundReadHeaderTimeout = 30 * time.Second

// httpInboundIdleTimeout caps idle keep-alive on per-account inbound HTTP
// servers; matches the host listener.
const httpInboundIdleTimeout = 90 * time.Second

// inboundShutdownTimeout caps how long a per-account http.Server gets to
// drain in-flight requests during teardown.
const inboundShutdownTimeout = 5 * time.Second

// privateInboundPortHTTPS is the WG-side TLS port. Each account's
// embedded netstack binds independently, so a fixed port is fine.
const privateInboundPortHTTPS = 443

// privateInboundPortHTTP is the WG-side plain-HTTP port.
const privateInboundPortHTTP = 80

// inboundManager wires per-account inbound listeners into the proxy
// pipeline when --private is enabled. When disabled the manager
// is nil and every method on *Server that touches it short-circuits.
type inboundManager struct {
	logger    *log.Logger
	handler   http.Handler
	tlsConfig *tls.Config
	// muxLock guards entries and pendingRoutes.
	muxLock       sync.Mutex
	entries       map[types.AccountID]*inboundEntry
	pendingRoutes map[types.AccountID][]pendingInboundRoute
}

// inboundEntry owns the listeners, router and HTTP servers for a single
// account's embedded netstack. errorLogWriters retain the logrus pipe
// writers backing each http.Server's ErrorLog so tearDown can close
// them — otherwise the pipe + its scanner goroutine leak per account.
type inboundEntry struct {
	router          *nbtcp.Router
	tlsListener     net.Listener
	plainListener   net.Listener
	httpsServer     *http.Server
	httpServer      *http.Server
	errorLogWriters []*io.PipeWriter
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// pendingInboundRoute holds a route that arrived before the account's
// listener finished starting.
type pendingInboundRoute struct {
	host  nbtcp.SNIHost
	route nbtcp.Route
}

// newInboundManager constructs a manager bound to the proxy's HTTP
// handler chain and TLS config.
func newInboundManager(logger *log.Logger, handler http.Handler, tlsConfig *tls.Config) *inboundManager {
	return &inboundManager{
		logger:        logger,
		handler:       handler,
		tlsConfig:     tlsConfig,
		entries:       make(map[types.AccountID]*inboundEntry),
		pendingRoutes: make(map[types.AccountID][]pendingInboundRoute),
	}
}

// onClientReady is registered with NetBird.SetClientLifecycle so the
// listener pair comes up exactly when the embedded client reports ready.
// The returned value is opaque to the roundtrip package; it is handed
// back verbatim to onClientStop on teardown.
func (m *inboundManager) onClientReady(ctx context.Context, accountID types.AccountID, client *embed.Client) any {
	if m == nil {
		return nil
	}
	entry, err := m.bringUp(ctx, accountID, client)
	if err != nil {
		m.logger.WithField("account_id", accountID).WithError(err).Warn("failed to start per-account inbound listener; continuing without inbound")
		return nil
	}

	m.flushPending(accountID, entry)

	m.logger.WithFields(log.Fields{
		"account_id": accountID,
		"https":      entry.tlsListener.Addr().String(),
		"http":       entry.plainListener.Addr().String(),
	}).Info("per-account inbound listeners up")
	return entry
}

// onClientStop tears down a per-account listener bundle. State is the
// opaque value previously returned by onClientReady.
func (m *inboundManager) onClientStop(accountID types.AccountID, state any) {
	if m == nil {
		return
	}
	entry, ok := state.(*inboundEntry)
	if !ok || entry == nil {
		return
	}
	m.tearDown(accountID, entry)
}

// bringUp opens both listeners on the account's netstack, builds the
// router, and starts the parallel HTTP servers.
func (m *inboundManager) bringUp(ctx context.Context, accountID types.AccountID, client *embed.Client) (*inboundEntry, error) {
	tlsListener, err := client.ListenTCP(fmt.Sprintf(":%d", privateInboundPortHTTPS))
	if err != nil {
		return nil, fmt.Errorf("listen tls on netstack: %w", err)
	}
	plainListener, err := client.ListenTCP(fmt.Sprintf(":%d", privateInboundPortHTTP))
	if err != nil {
		_ = tlsListener.Close()
		return nil, fmt.Errorf("listen plain on netstack: %w", err)
	}

	router := nbtcp.NewRouter(m.logger, accountDialResolver(accountID, client), tlsListener.Addr(), nbtcp.WithPlainHTTP(plainListener.Addr()))

	scopedHandler := withTunnelLookup(m.handler, accountTunnelLookup(client))

	// markOverlayOrigin stamps every connection accepted by an inbound
	// listener with a context value middlewares can read to skip
	// geo/CrowdSec checks (the source address is always inside the
	// NetBird CGNAT range and won't match either dataset).
	markOverlayOrigin := func(ctx context.Context, _ net.Conn) context.Context {
		return types.WithOverlayOrigin(ctx)
	}

	httpsErrLog, httpsErrW := newInboundErrorLog(m.logger, "https", accountID)
	httpErrLog, httpErrW := newInboundErrorLog(m.logger, "http", accountID)

	httpsServer := &http.Server{
		Handler:           scopedHandler,
		TLSConfig:         m.tlsConfig,
		ReadHeaderTimeout: httpInboundReadHeaderTimeout,
		IdleTimeout:       httpInboundIdleTimeout,
		ErrorLog:          httpsErrLog,
		ConnContext:       markOverlayOrigin,
	}
	httpServer := &http.Server{
		Handler:           scopedHandler,
		ReadHeaderTimeout: httpInboundReadHeaderTimeout,
		IdleTimeout:       httpInboundIdleTimeout,
		ErrorLog:          httpErrLog,
		ConnContext:       markOverlayOrigin,
	}

	runCtx, cancel := context.WithCancel(ctx)
	entry := &inboundEntry{
		router:          router,
		tlsListener:     tlsListener,
		plainListener:   plainListener,
		httpsServer:     httpsServer,
		httpServer:      httpServer,
		errorLogWriters: []*io.PipeWriter{httpsErrW, httpErrW},
		cancel:          cancel,
	}

	entry.wg.Add(1)
	go func() {
		defer entry.wg.Done()
		if err := router.Serve(runCtx, tlsListener); err != nil {
			m.logger.WithField("account_id", accountID).Debugf("per-account router stopped: %v", err)
		}
	}()

	entry.wg.Add(1)
	go func() {
		defer entry.wg.Done()
		if err := httpsServer.ServeTLS(router.HTTPListener(), "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logger.WithField("account_id", accountID).Debugf("per-account https server stopped: %v", err)
		}
	}()

	entry.wg.Add(1)
	go func() {
		defer entry.wg.Done()
		if err := httpServer.Serve(router.HTTPListenerPlain()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logger.WithField("account_id", accountID).Debugf("per-account http server stopped: %v", err)
		}
	}()

	entry.wg.Add(1)
	go func() {
		defer entry.wg.Done()
		feedRouterFromListener(runCtx, plainListener, router, m.logger, accountID)
	}()

	m.muxLock.Lock()
	m.entries[accountID] = entry
	m.muxLock.Unlock()

	return entry, nil
}

// tearDown shuts every goroutine down and closes the netstack listeners.
func (m *inboundManager) tearDown(accountID types.AccountID, entry *inboundEntry) {
	m.muxLock.Lock()
	if m.entries[accountID] == entry {
		delete(m.entries, accountID)
		delete(m.pendingRoutes, accountID)
	}
	m.muxLock.Unlock()

	entry.cancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), inboundShutdownTimeout)
	defer cancel()

	if err := entry.httpsServer.Shutdown(shutdownCtx); err != nil {
		m.logger.Debugf("per-account https shutdown: %v", err)
	}
	if err := entry.httpServer.Shutdown(shutdownCtx); err != nil {
		m.logger.Debugf("per-account http shutdown: %v", err)
	}
	if err := entry.tlsListener.Close(); err != nil {
		m.logger.Debugf("close per-account tls listener: %v", err)
	}
	if err := entry.plainListener.Close(); err != nil {
		m.logger.Debugf("close per-account plain listener: %v", err)
	}
	entry.wg.Wait()
	// Close the ErrorLog pipes only after the http.Servers have fully
	// stopped so any straggling stdlib write doesn't race with the
	// close. Each writer also tears down the logrus scanner goroutine.
	for _, w := range entry.errorLogWriters {
		if err := w.Close(); err != nil {
			m.logger.Debugf("close per-account inbound error log writer: %v", err)
		}
	}
}

// AddRoute records an SNI/host route on the account's per-account router.
// Routes registered before the listener is up are queued and replayed
// once startup completes.
func (m *inboundManager) AddRoute(accountID types.AccountID, host nbtcp.SNIHost, route nbtcp.Route) {
	if m == nil {
		return
	}
	m.muxLock.Lock()
	entry, ok := m.entries[accountID]
	if !ok {
		m.queuePendingLocked(accountID, host, route)
		m.muxLock.Unlock()
		return
	}
	router := entry.router
	m.muxLock.Unlock()

	router.AddRoute(host, route)
}

// RemoveRoute drops a previously registered route. Safe to call when the
// listener is not yet up; queued copies are pruned in that case.
func (m *inboundManager) RemoveRoute(accountID types.AccountID, host nbtcp.SNIHost, svcID types.ServiceID) {
	if m == nil {
		return
	}
	m.muxLock.Lock()
	m.dropPendingLocked(accountID, host, svcID)
	entry, ok := m.entries[accountID]
	if !ok {
		m.muxLock.Unlock()
		return
	}
	router := entry.router
	m.muxLock.Unlock()

	router.RemoveRoute(host, svcID)
}

// queuePendingLocked stores or upserts a pending route. Caller holds muxLock.
func (m *inboundManager) queuePendingLocked(accountID types.AccountID, host nbtcp.SNIHost, route nbtcp.Route) {
	queued := m.pendingRoutes[accountID]
	for i, pr := range queued {
		if pr.host == host && pr.route.ServiceID == route.ServiceID {
			queued[i] = pendingInboundRoute{host: host, route: route}
			m.pendingRoutes[accountID] = queued
			return
		}
	}
	m.pendingRoutes[accountID] = append(queued, pendingInboundRoute{host: host, route: route})
}

// dropPendingLocked removes any queued route matching host/svcID.
// Caller holds muxLock.
func (m *inboundManager) dropPendingLocked(accountID types.AccountID, host nbtcp.SNIHost, svcID types.ServiceID) {
	queued, ok := m.pendingRoutes[accountID]
	if !ok {
		return
	}
	filtered := queued[:0]
	for _, pr := range queued {
		if pr.host == host && pr.route.ServiceID == svcID {
			continue
		}
		filtered = append(filtered, pr)
	}
	if len(filtered) == 0 {
		delete(m.pendingRoutes, accountID)
		return
	}
	m.pendingRoutes[accountID] = filtered
}

// flushPending applies all queued routes to a freshly-up router.
func (m *inboundManager) flushPending(accountID types.AccountID, entry *inboundEntry) {
	m.muxLock.Lock()
	queued := m.pendingRoutes[accountID]
	delete(m.pendingRoutes, accountID)
	m.muxLock.Unlock()

	for _, pr := range queued {
		entry.router.AddRoute(pr.host, pr.route)
	}
}

// HasInbound reports whether the manager has a live listener for the account.
// Used by tests.
func (m *inboundManager) HasInbound(accountID types.AccountID) bool {
	if m == nil {
		return false
	}
	m.muxLock.Lock()
	defer m.muxLock.Unlock()
	_, ok := m.entries[accountID]
	return ok
}

// PendingRouteCount reports the number of queued routes for the account.
// Used by tests.
func (m *inboundManager) PendingRouteCount(accountID types.AccountID) int {
	if m == nil {
		return 0
	}
	m.muxLock.Lock()
	defer m.muxLock.Unlock()
	return len(m.pendingRoutes[accountID])
}

// InboundListenerInfo describes the bound addresses of a single
// per-account inbound listener. Both addresses live on the embedded
// netstack of the account's WireGuard client and share the same tunnel IP.
type InboundListenerInfo struct {
	TunnelIP  string
	HTTPSPort uint16
	HTTPPort  uint16
}

// ListenerInfo returns the inbound listener addresses for the given
// account, or ok=false when the account has no live listener. Used by
// the status-update RPC and the debug HTTP handler to surface inbound
// reachability to operators.
func (m *inboundManager) ListenerInfo(accountID types.AccountID) (InboundListenerInfo, bool) {
	if m == nil {
		return InboundListenerInfo{}, false
	}
	m.muxLock.Lock()
	defer m.muxLock.Unlock()
	entry, ok := m.entries[accountID]
	if !ok || entry == nil {
		return InboundListenerInfo{}, false
	}
	return listenerInfoFromEntry(entry), true
}

// Snapshot returns the inbound listener state for every account that has
// a live listener at call time. Empty when --private is off or
// no accounts have come up yet.
func (m *inboundManager) Snapshot() map[types.AccountID]InboundListenerInfo {
	if m == nil {
		return nil
	}
	m.muxLock.Lock()
	defer m.muxLock.Unlock()
	if len(m.entries) == 0 {
		return nil
	}
	out := make(map[types.AccountID]InboundListenerInfo, len(m.entries))
	for id, entry := range m.entries {
		if entry == nil {
			continue
		}
		out[id] = listenerInfoFromEntry(entry)
	}
	return out
}

// listenerInfoFromEntry extracts the tunnel IP and ports from a live
// per-account entry. Both listeners are bound on the same netstack so
// their host components match; we still pull the TLS host as the
// authoritative source.
func listenerInfoFromEntry(entry *inboundEntry) InboundListenerInfo {
	info := InboundListenerInfo{HTTPSPort: privateInboundPortHTTPS, HTTPPort: privateInboundPortHTTP}
	if entry.tlsListener != nil {
		host, port := splitHostPort(entry.tlsListener.Addr())
		info.TunnelIP = host
		if port != 0 {
			info.HTTPSPort = port
		}
	}
	if entry.plainListener != nil {
		host, port := splitHostPort(entry.plainListener.Addr())
		if info.TunnelIP == "" {
			info.TunnelIP = host
		}
		if port != 0 {
			info.HTTPPort = port
		}
	}
	return info
}

// splitHostPort extracts host and port from a net.Addr, returning the
// zero values when the address is missing or malformed.
func splitHostPort(addr net.Addr) (string, uint16) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	if portStr == "" {
		return host, 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return host, 0
	}
	return host, uint16(port)
}

// feedRouterFromListener accepts on the plain-HTTP netstack listener and
// hands every connection to the account's router. The router peeks the
// first byte and dispatches to the plain-HTTP channel for non-TLS
// streams or the TLS channel for ClientHellos that arrive on :80.
func feedRouterFromListener(ctx context.Context, ln net.Listener, router *nbtcp.Router, logger *log.Logger, accountID types.AccountID) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var backoff nbtcp.AcceptBackoff
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || nbtcp.IsClosedListenerErr(err) {
				return
			}
			logger.WithField("account_id", accountID).Debugf("plain inbound accept: %v; backing off", err)
			if !backoff.Backoff(ctx) {
				return
			}
			continue
		}
		backoff.Reset()
		router.HandleConn(ctx, conn)
	}
}

// accountDialResolver returns a DialResolver bound to a single account's
// embedded client. The router only ever serves traffic for that account
// so the supplied accountID is ignored at dial time.
func accountDialResolver(_ types.AccountID, client *embed.Client) nbtcp.DialResolver {
	return func(_ types.AccountID) (types.DialContextFunc, error) {
		return client.DialContext, nil
	}
}

// accountTunnelLookup returns a TunnelLookupFunc backed by the embedded
// client's peerstore for a single account. Phase 3 uses the result to
// short-circuit ValidateTunnelPeer when the source IP is not in the
// account's roster and to seed the cached identity for known peers.
func accountTunnelLookup(client *embed.Client) auth.TunnelLookupFunc {
	if client == nil {
		return nil
	}
	return func(ip netip.Addr) (auth.PeerIdentity, bool) {
		pubKey, fqdn, ok := client.IdentityForIP(ip)
		if !ok {
			return auth.PeerIdentity{}, false
		}
		return auth.PeerIdentity{
			PubKey:   pubKey,
			TunnelIP: ip,
			FQDN:     fqdn,
		}, true
	}
}

// withTunnelLookup returns an http.Handler that attaches the per-account
// peerstore lookup to every request's context before delegating to next.
// Calling on the host-level listener is a no-op because that path never
// installs this wrapper, so the existing behaviour stays byte-for-byte
// identical when --private is off or the request didn't arrive
// on a per-account listener.
func withTunnelLookup(next http.Handler, lookup auth.TunnelLookupFunc) http.Handler {
	if lookup == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithTunnelLookup(r.Context(), lookup)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// inboundDebugAdapter adapts *inboundManager to the debug.InboundProvider
// interface so the debug HTTP handler can render per-account inbound
// listener state without importing the proxy package.
type inboundDebugAdapter struct {
	mgr *inboundManager
}

// InboundListeners returns a snapshot of the live per-account inbound
// listeners formatted for the debug surface.
func (a inboundDebugAdapter) InboundListeners() map[types.AccountID]debug.InboundListenerInfo {
	if a.mgr == nil {
		return nil
	}
	snap := a.mgr.Snapshot()
	if len(snap) == 0 {
		return nil
	}
	out := make(map[types.AccountID]debug.InboundListenerInfo, len(snap))
	for id, info := range snap {
		out[id] = debug.InboundListenerInfo{
			TunnelIP:  info.TunnelIP,
			HTTPSPort: info.HTTPSPort,
			HTTPPort:  info.HTTPPort,
		}
	}
	return out
}

// newInboundErrorLog routes a per-account http.Server's stdlib error
// stream through logrus at warn level. The returned PipeWriter must be
// closed by the caller (tearDown) once the http.Server has shut down —
// otherwise the pipe and its scanner goroutine leak per account, see
// logrus.Entry.WriterLevel.
func newInboundErrorLog(logger *log.Logger, scheme string, accountID types.AccountID) (*stdlog.Logger, *io.PipeWriter) {
	w := logger.WithFields(log.Fields{
		"inbound-http": scheme,
		"account_id":   accountID,
	}).WriterLevel(log.WarnLevel)
	return stdlog.New(w, "", 0), w
}
