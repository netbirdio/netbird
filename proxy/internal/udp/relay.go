package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/netutil"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

const (
	// DefaultSessionTTL is the default idle timeout for UDP sessions before cleanup.
	DefaultSessionTTL = 30 * time.Second
	// cleanupInterval is how often the cleaner goroutine runs.
	cleanupInterval = time.Minute
	// maxPacketSize is the maximum UDP packet size we'll handle.
	maxPacketSize = 65535
	// DefaultMaxSessions is the default cap on concurrent UDP sessions per relay.
	DefaultMaxSessions = 1024
	// sessionCreateRate limits new session creation per second.
	sessionCreateRate = 50
	// sessionCreateBurst is the burst allowance for session creation.
	sessionCreateBurst = 100
	// defaultDialTimeout is the fallback dial timeout for backend connections.
	defaultDialTimeout = 30 * time.Second
)

// l4Logger sends layer-4 access log entries to the management server.
type l4Logger interface {
	LogL4(entry accesslog.L4Entry)
}

// SessionObserver receives callbacks for UDP session lifecycle events.
// All methods must be safe for concurrent use.
type SessionObserver interface {
	UDPSessionStarted(accountID types.AccountID)
	UDPSessionEnded(accountID types.AccountID)
	UDPSessionDialError(accountID types.AccountID)
	UDPSessionRejected(accountID types.AccountID)
	UDPPacketRelayed(direction types.RelayDirection, bytes int)
}

// clientAddr is a typed key for UDP session lookups.
type clientAddr string

// Relay listens for incoming UDP packets on a dedicated port and
// maintains per-client sessions that relay packets to a backend
// through the WireGuard tunnel.
type Relay struct {
	logger      *log.Entry
	listener    net.PacketConn
	target      string
	domain      string
	accountID   types.AccountID
	serviceID   types.ServiceID
	dialFunc    types.DialContextFunc
	dialTimeout time.Duration
	sessionTTL  time.Duration
	maxSessions int
	filter      *restrict.Filter
	geo         restrict.GeoResolver

	mu       sync.RWMutex
	sessions map[clientAddr]*session

	bufPool     sync.Pool
	sessLimiter *rate.Limiter
	sessWg      sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	observer    SessionObserver
	accessLog   l4Logger
}

type session struct {
	backend   net.Conn
	addr      net.Addr
	createdAt time.Time
	// lastSeen stores the last activity timestamp as unix nanoseconds.
	lastSeen atomic.Int64
	cancel   context.CancelFunc
	// bytesIn tracks total bytes received from the client.
	bytesIn atomic.Int64
	// bytesOut tracks total bytes sent back to the client.
	bytesOut atomic.Int64
}

func (s *session) updateLastSeen() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *session) idleDuration() time.Duration {
	return time.Since(time.Unix(0, s.lastSeen.Load()))
}

// RelayConfig holds the configuration for a UDP relay.
type RelayConfig struct {
	Logger      *log.Entry
	Listener    net.PacketConn
	Target      string
	Domain      string
	AccountID   types.AccountID
	ServiceID   types.ServiceID
	DialFunc    types.DialContextFunc
	DialTimeout time.Duration
	SessionTTL  time.Duration
	MaxSessions int
	AccessLog   l4Logger
	// Filter holds connection-level IP/geo restrictions. Nil means no restrictions.
	Filter *restrict.Filter
	// Geo is the geolocation lookup used for country-based restrictions.
	Geo restrict.GeoResolver
}

// New creates a UDP relay for the given listener and backend target.
// MaxSessions caps the number of concurrent sessions; use 0 for DefaultMaxSessions.
// DialTimeout controls how long to wait for backend connections; use 0 for default.
// SessionTTL is the idle timeout before a session is reaped; use 0 for DefaultSessionTTL.
func New(parentCtx context.Context, cfg RelayConfig) *Relay {
	maxSessions := cfg.MaxSessions
	dialTimeout := cfg.DialTimeout
	sessionTTL := cfg.SessionTTL
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	ctx, cancel := context.WithCancel(parentCtx)
	return &Relay{
		logger:      cfg.Logger,
		listener:    cfg.Listener,
		target:      cfg.Target,
		domain:      cfg.Domain,
		accountID:   cfg.AccountID,
		serviceID:   cfg.ServiceID,
		accessLog:   cfg.AccessLog,
		dialFunc:    cfg.DialFunc,
		dialTimeout: dialTimeout,
		sessionTTL:  sessionTTL,
		maxSessions: maxSessions,
		filter:      cfg.Filter,
		geo:         cfg.Geo,
		sessions:    make(map[clientAddr]*session),
		bufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, maxPacketSize)
				return &buf
			},
		},
		sessLimiter: rate.NewLimiter(sessionCreateRate, sessionCreateBurst),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// ServiceID returns the service ID associated with this relay.
func (r *Relay) ServiceID() types.ServiceID {
	return r.serviceID
}

// SetObserver sets the session lifecycle observer. Must be called before Serve.
func (r *Relay) SetObserver(obs SessionObserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observer = obs
}

// getObserver returns the current session lifecycle observer.
func (r *Relay) getObserver() SessionObserver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.observer
}

// Serve starts the relay loop. It blocks until the context is canceled
// or the listener is closed.
func (r *Relay) Serve() {
	go r.cleanupLoop()

	for {
		bufp := r.bufPool.Get().(*[]byte)
		buf := *bufp

		n, addr, err := r.listener.ReadFrom(buf)
		if err != nil {
			r.bufPool.Put(bufp)
			if r.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			r.logger.Debugf("UDP read: %v", err)
			continue
		}

		data := buf[:n]
		sess, err := r.getOrCreateSession(addr)
		if err != nil {
			r.bufPool.Put(bufp)
			r.logger.Debugf("create UDP session for %s: %v", addr, err)
			continue
		}

		sess.updateLastSeen()

		nw, err := sess.backend.Write(data)
		if err != nil {
			r.bufPool.Put(bufp)
			if !netutil.IsExpectedError(err) {
				r.logger.Debugf("UDP write to backend for %s: %v", addr, err)
			}
			r.removeSession(sess)
			continue
		}
		sess.bytesIn.Add(int64(nw))

		if obs := r.getObserver(); obs != nil {
			obs.UDPPacketRelayed(types.RelayDirectionClientToBackend, nw)
		}
		r.bufPool.Put(bufp)
	}
}

// getOrCreateSession returns an existing session or creates a new one.
func (r *Relay) getOrCreateSession(addr net.Addr) (*session, error) {
	key := clientAddr(addr.String())

	r.mu.RLock()
	sess, ok := r.sessions[key]
	r.mu.RUnlock()
	if ok && sess != nil {
		return sess, nil
	}

	// Check before taking the write lock: if the relay is shutting down,
	// don't create new sessions. This prevents orphaned goroutines when
	// Serve() processes a packet that was already read before Close().
	if r.ctx.Err() != nil {
		return nil, r.ctx.Err()
	}

	if err := r.checkAccessRestrictions(addr); err != nil {
		return nil, err
	}

	r.mu.Lock()

	if sess, ok = r.sessions[key]; ok && sess != nil {
		r.mu.Unlock()
		return sess, nil
	}
	if ok {
		// Another goroutine is dialing for this key, skip.
		r.mu.Unlock()
		return nil, fmt.Errorf("session dial in progress for %s", key)
	}

	if len(r.sessions) >= r.maxSessions {
		r.mu.Unlock()
		if obs := r.getObserver(); obs != nil {
			obs.UDPSessionRejected(r.accountID)
		}
		return nil, fmt.Errorf("session limit reached (%d)", r.maxSessions)
	}

	if !r.sessLimiter.Allow() {
		r.mu.Unlock()
		if obs := r.getObserver(); obs != nil {
			obs.UDPSessionRejected(r.accountID)
		}
		return nil, fmt.Errorf("session creation rate limited")
	}

	// Reserve the slot with a nil session so concurrent callers for the same
	// key see it exists and wait. Release the lock before dialing.
	r.sessions[key] = nil
	r.mu.Unlock()

	dialCtx, dialCancel := context.WithTimeout(r.ctx, r.dialTimeout)
	backend, err := r.dialFunc(dialCtx, "udp", r.target)
	dialCancel()
	if err != nil {
		r.mu.Lock()
		delete(r.sessions, key)
		r.mu.Unlock()
		if obs := r.getObserver(); obs != nil {
			obs.UDPSessionDialError(r.accountID)
		}
		return nil, fmt.Errorf("dial backend %s: %w", r.target, err)
	}

	sessCtx, sessCancel := context.WithCancel(r.ctx)
	sess = &session{
		backend:   backend,
		addr:      addr,
		createdAt: time.Now(),
		cancel:    sessCancel,
	}
	sess.updateLastSeen()

	r.mu.Lock()
	r.sessions[key] = sess
	r.mu.Unlock()

	if obs := r.getObserver(); obs != nil {
		obs.UDPSessionStarted(r.accountID)
	}

	r.sessWg.Go(func() {
		r.relayBackendToClient(sessCtx, sess)
	})

	r.logger.Debugf("UDP session created for %s", addr)
	return sess, nil
}

func (r *Relay) checkAccessRestrictions(addr net.Addr) error {
	if r.filter == nil {
		return nil
	}
	clientIP, err := addrFromUDPAddr(addr)
	if err != nil {
		return fmt.Errorf("parse client address %s for restriction check: %w", addr, err)
	}
	if v := r.filter.Check(clientIP, r.geo); v != restrict.Allow {
		if r.filter.IsObserveOnly(v) {
			r.logger.Debugf("CrowdSec observe: would block %s (%s)", clientIP, v)
			r.logDeny(clientIP, v, true)
		} else {
			r.logDeny(clientIP, v, false)
			return fmt.Errorf("access restricted for %s", addr)
		}
	}
	return nil
}

// relayBackendToClient reads packets from the backend and writes them
// back to the client through the public-facing listener.
func (r *Relay) relayBackendToClient(ctx context.Context, sess *session) {
	bufp := r.bufPool.Get().(*[]byte)
	defer r.bufPool.Put(bufp)
	defer r.removeSession(sess)

	for ctx.Err() == nil {
		data, ok := r.readBackendPacket(sess, *bufp)
		if !ok {
			return
		}
		if data == nil {
			continue
		}

		sess.updateLastSeen()

		nw, err := r.listener.WriteTo(data, sess.addr)
		if err != nil {
			if !netutil.IsExpectedError(err) {
				r.logger.Debugf("UDP write to client %s: %v", sess.addr, err)
			}
			return
		}
		sess.bytesOut.Add(int64(nw))

		if obs := r.getObserver(); obs != nil {
			obs.UDPPacketRelayed(types.RelayDirectionBackendToClient, nw)
		}
	}
}

// readBackendPacket reads one packet from the backend with an idle deadline.
// Returns (data, true) on success, (nil, true) on idle timeout that should
// retry, or (nil, false) when the session should be torn down.
func (r *Relay) readBackendPacket(sess *session, buf []byte) ([]byte, bool) {
	if err := sess.backend.SetReadDeadline(time.Now().Add(r.sessionTTL)); err != nil {
		r.logger.Debugf("set backend read deadline for %s: %v", sess.addr, err)
		return nil, false
	}

	n, err := sess.backend.Read(buf)
	if err != nil {
		if netutil.IsTimeout(err) {
			if sess.idleDuration() > r.sessionTTL {
				return nil, false
			}
			return nil, true
		}
		if !netutil.IsExpectedError(err) {
			r.logger.Debugf("UDP read from backend for %s: %v", sess.addr, err)
		}
		return nil, false
	}

	return buf[:n], true
}

// cleanupLoop periodically removes idle sessions.
func (r *Relay) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.cleanupIdleSessions()
		}
	}
}

// cleanupIdleSessions closes sessions that have been idle for too long.
func (r *Relay) cleanupIdleSessions() {
	var expired []*session

	r.mu.Lock()
	for key, sess := range r.sessions {
		if sess == nil {
			continue
		}
		idle := sess.idleDuration()
		if idle > r.sessionTTL {
			r.logger.Debugf("UDP session %s idle for %s, closing (client→backend: %d bytes, backend→client: %d bytes)",
				sess.addr, idle, sess.bytesIn.Load(), sess.bytesOut.Load())
			delete(r.sessions, key)
			sess.cancel()
			if err := sess.backend.Close(); err != nil {
				r.logger.Debugf("close idle session %s backend: %v", sess.addr, err)
			}
			expired = append(expired, sess)
		}
	}
	r.mu.Unlock()

	obs := r.getObserver()
	for _, sess := range expired {
		if obs != nil {
			obs.UDPSessionEnded(r.accountID)
		}
		r.logSessionEnd(sess)
	}
}

// removeSession removes a session from the map if it still matches the
// given pointer. This is safe to call concurrently with cleanupIdleSessions
// because the identity check prevents double-close when both paths race.
func (r *Relay) removeSession(sess *session) {
	r.mu.Lock()
	key := clientAddr(sess.addr.String())
	removed := r.sessions[key] == sess
	if removed {
		delete(r.sessions, key)
		sess.cancel()
		if err := sess.backend.Close(); err != nil {
			r.logger.Debugf("close session %s backend: %v", sess.addr, err)
		}
	}
	r.mu.Unlock()

	if removed {
		r.logger.Debugf("UDP session %s ended (client→backend: %d bytes, backend→client: %d bytes)",
			sess.addr, sess.bytesIn.Load(), sess.bytesOut.Load())
		if obs := r.getObserver(); obs != nil {
			obs.UDPSessionEnded(r.accountID)
		}
		r.logSessionEnd(sess)
	}
}

// logSessionEnd sends an access log entry for a completed UDP session.
func (r *Relay) logSessionEnd(sess *session) {
	if r.accessLog == nil {
		return
	}

	var sourceIP netip.Addr
	if ap, err := netip.ParseAddrPort(sess.addr.String()); err == nil {
		sourceIP = ap.Addr().Unmap()
	}

	r.accessLog.LogL4(accesslog.L4Entry{
		AccountID:     r.accountID,
		ServiceID:     r.serviceID,
		Protocol:      accesslog.ProtocolUDP,
		Host:          r.domain,
		SourceIP:      sourceIP,
		DurationMs:    time.Unix(0, sess.lastSeen.Load()).Sub(sess.createdAt).Milliseconds(),
		BytesUpload:   sess.bytesIn.Load(),
		BytesDownload: sess.bytesOut.Load(),
	})
}

// logDeny sends an access log entry for a denied UDP packet.
func (r *Relay) logDeny(clientIP netip.Addr, verdict restrict.Verdict, observeOnly bool) {
	if r.accessLog == nil {
		return
	}

	entry := accesslog.L4Entry{
		AccountID:  r.accountID,
		ServiceID:  r.serviceID,
		Protocol:   accesslog.ProtocolUDP,
		Host:       r.domain,
		SourceIP:   clientIP,
		DenyReason: verdict.String(),
	}
	if verdict.IsCrowdSec() {
		entry.Metadata = map[string]string{"crowdsec_verdict": verdict.String()}
		if observeOnly {
			entry.Metadata["crowdsec_mode"] = "observe"
			entry.DenyReason = ""
		}
	}
	r.accessLog.LogL4(entry)
}

// Close stops the relay, waits for all session goroutines to exit,
// and cleans up remaining sessions.
func (r *Relay) Close() {
	r.cancel()
	if err := r.listener.Close(); err != nil {
		r.logger.Debugf("close UDP listener: %v", err)
	}

	var closedSessions []*session
	r.mu.Lock()
	for key, sess := range r.sessions {
		if sess == nil {
			delete(r.sessions, key)
			continue
		}
		r.logger.Debugf("UDP session %s closed (client→backend: %d bytes, backend→client: %d bytes)",
			sess.addr, sess.bytesIn.Load(), sess.bytesOut.Load())
		sess.cancel()
		if err := sess.backend.Close(); err != nil {
			r.logger.Debugf("close session %s backend: %v", sess.addr, err)
		}
		delete(r.sessions, key)
		closedSessions = append(closedSessions, sess)
	}
	r.mu.Unlock()

	obs := r.getObserver()
	for _, sess := range closedSessions {
		if obs != nil {
			obs.UDPSessionEnded(r.accountID)
		}
		r.logSessionEnd(sess)
	}

	r.sessWg.Wait()
}

// addrFromUDPAddr extracts a netip.Addr from a net.Addr.
func addrFromUDPAddr(addr net.Addr) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}
