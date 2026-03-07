package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/proxy/internal/netutil"
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

// SessionObserver receives callbacks for UDP session lifecycle events.
// All methods must be safe for concurrent use.
type SessionObserver interface {
	UDPSessionStarted(accountID string)
	UDPSessionEnded(accountID string)
	UDPSessionDialError(accountID string)
	UDPSessionRejected(accountID string)
	UDPPacketRelayed(direction types.RelayDirection, bytes int)
}

// clientAddr is a typed key for UDP session lookups.
type clientAddr = string

// Relay listens for incoming UDP packets on a dedicated port and
// maintains per-client sessions that relay packets to a backend
// through the WireGuard tunnel.
type Relay struct {
	logger      *log.Entry
	listener    net.PacketConn
	target      string
	accountID   types.AccountID
	dialFunc    types.DialContextFunc
	dialTimeout time.Duration
	sessionTTL  time.Duration
	maxSessions int

	mu       sync.RWMutex
	sessions map[clientAddr]*session

	bufPool     sync.Pool
	sessLimiter *rate.Limiter
	sessWg      sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	observer    SessionObserver
}

type session struct {
	backend net.Conn
	addr    net.Addr
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
	AccountID   types.AccountID
	DialFunc    types.DialContextFunc
	DialTimeout time.Duration
	SessionTTL  time.Duration
	MaxSessions int
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
		accountID:   cfg.AccountID,
		dialFunc:    cfg.DialFunc,
		dialTimeout: dialTimeout,
		sessionTTL:  sessionTTL,
		maxSessions: maxSessions,
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

// SetObserver sets the session lifecycle observer. Must be called before Serve.
func (r *Relay) SetObserver(obs SessionObserver) {
	r.observer = obs
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

		if r.observer != nil {
			r.observer.UDPPacketRelayed(types.RelayDirectionClientToBackend, nw)
		}
		r.bufPool.Put(bufp)
	}
}

// getOrCreateSession returns an existing session or creates a new one.
func (r *Relay) getOrCreateSession(addr net.Addr) (*session, error) {
	key := addr.String()

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
		if r.observer != nil {
			r.observer.UDPSessionRejected(string(r.accountID))
		}
		return nil, fmt.Errorf("session limit reached (%d)", r.maxSessions)
	}

	if !r.sessLimiter.Allow() {
		r.mu.Unlock()
		if r.observer != nil {
			r.observer.UDPSessionRejected(string(r.accountID))
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
		if r.observer != nil {
			r.observer.UDPSessionDialError(string(r.accountID))
		}
		return nil, fmt.Errorf("dial backend %s: %w", r.target, err)
	}

	sessCtx, sessCancel := context.WithCancel(r.ctx)
	sess = &session{
		backend: backend,
		addr:    addr,
		cancel:  sessCancel,
	}
	sess.updateLastSeen()

	r.mu.Lock()
	r.sessions[key] = sess
	r.mu.Unlock()

	if r.observer != nil {
		r.observer.UDPSessionStarted(string(r.accountID))
	}

	r.sessWg.Go(func() {
		r.relayBackendToClient(sessCtx, sess)
	})

	r.logger.Debugf("UDP session created for %s", addr)
	return sess, nil
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

		if r.observer != nil {
			r.observer.UDPPacketRelayed(types.RelayDirectionBackendToClient, nw)
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
	var cleaned int

	r.mu.Lock()
	for key, sess := range r.sessions {
		if sess == nil {
			continue
		}
		idle := sess.idleDuration()
		if idle > r.sessionTTL {
			r.logger.Debugf("UDP session %s idle for %s, closing (client→backend: %d bytes, backend→client: %d bytes)",
				sess.addr, idle, sess.bytesIn.Load(), sess.bytesOut.Load())
			// Delete before closing so getOrCreateSession never returns
			// a stale entry whose backend is being torn down.
			delete(r.sessions, key)
			sess.cancel()
			if err := sess.backend.Close(); err != nil {
				r.logger.Debugf("close idle session %s backend: %v", sess.addr, err)
			}
			cleaned++
		}
	}
	r.mu.Unlock()

	if r.observer != nil {
		for range cleaned {
			r.observer.UDPSessionEnded(string(r.accountID))
		}
	}
}

// removeSession removes a session from the map if it still matches the
// given pointer. This is safe to call concurrently with cleanupIdleSessions
// because the identity check prevents double-close when both paths race.
func (r *Relay) removeSession(sess *session) {
	r.mu.Lock()
	key := sess.addr.String()
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
		if r.observer != nil {
			r.observer.UDPSessionEnded(string(r.accountID))
		}
	}
}

// Close stops the relay, waits for all session goroutines to exit,
// and cleans up remaining sessions.
func (r *Relay) Close() {
	r.cancel()
	if err := r.listener.Close(); err != nil {
		r.logger.Debugf("close UDP listener: %v", err)
	}

	var closed int
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
		closed++
	}
	r.mu.Unlock()

	if r.observer != nil {
		for range closed {
			r.observer.UDPSessionEnded(string(r.accountID))
		}
	}

	r.sessWg.Wait()
}
