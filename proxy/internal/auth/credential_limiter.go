package auth

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

const (
	credentialFailureLimit    = 5
	credentialFailureWindow   = 5 * time.Minute
	credentialBlockDuration   = 15 * time.Minute
	credentialCheckInterval   = 6 * time.Second
	credentialCheckBurst      = 5
	credentialMaxSources      = 16384
	credentialMaxServices     = 4096
	credentialCleanupInterval = time.Minute
)

type credentialServiceKey struct {
	accountID types.AccountID
	serviceID types.ServiceID
}

type credentialSourceKey struct {
	service credentialServiceKey
	ip      netip.Addr
}

type credentialSource struct {
	failures     []time.Time
	pending      int
	expiresAt    time.Time
	blockedUntil time.Time
}

type credentialService struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

type credentialOutcome string

const (
	credentialUnavailable credentialOutcome = "unavailable"
	credentialRejected    credentialOutcome = "rejected"
	credentialAccepted    credentialOutcome = "accepted"
)

// State is local to this proxy process. Active blocks are never evicted to
// make room for a new source; exhausting capacity denies new checks.
type credentialLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	sources     map[credentialSourceKey]*credentialSource
	services    map[credentialServiceKey]*credentialService
	nextCleanup time.Time
}

func newCredentialLimiter() *credentialLimiter {
	return &credentialLimiter{
		now:      time.Now,
		sources:  make(map[credentialSourceKey]*credentialSource),
		services: make(map[credentialServiceKey]*credentialService),
	}
}

func (l *credentialLimiter) begin(key credentialSourceKey) (*credentialSource, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.cleanup(now)
	source := l.sources[key]
	if source != nil {
		if now.Before(source.blockedUntil) {
			return nil, source.blockedUntil.Sub(now)
		}
		if source.pending == 0 && !now.Before(source.expiresAt) {
			*source = credentialSource{}
		}
		source.expireFailures(now)
		// Reserve the failure budget before verification so concurrent guesses
		// cannot all pass a check against the same completed failure count.
		if len(source.failures)+source.pending >= credentialFailureLimit {
			return nil, time.Second
		}
	} else if len(l.sources) >= credentialMaxSources {
		return nil, credentialCleanupInterval
	}
	if retry := l.allowService(key.service, now); retry > 0 {
		return nil, retry
	}
	if source == nil {
		source = &credentialSource{}
		l.sources[key] = source
	}
	if source.expiresAt.IsZero() {
		source.expiresAt = now.Add(credentialFailureWindow)
	}
	source.pending++
	return source, 0
}

func (l *credentialLimiter) allowService(key credentialServiceKey, now time.Time) time.Duration {
	service := l.services[key]
	if service == nil {
		if len(l.services) >= credentialMaxServices {
			return credentialCleanupInterval
		}
		service = &credentialService{limiter: rate.NewLimiter(rate.Every(credentialCheckInterval), credentialCheckBurst)}
		l.services[key] = service
	}
	service.lastUsed = now
	if service.limiter.AllowN(now, 1) {
		return 0
	}
	return max(time.Nanosecond, time.Duration((1-service.limiter.TokensAt(now))*float64(credentialCheckInterval)))
}

func (l *credentialLimiter) finish(source *credentialSource, outcome credentialOutcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	source.pending--
	now := l.now()
	source.expireFailures(now)
	switch outcome {
	case credentialRejected:
		source.failures = append(source.failures, now)
		source.expiresAt = now.Add(credentialFailureWindow)
		if len(source.failures) >= credentialFailureLimit && source.blockedUntil.IsZero() {
			source.blockedUntil = now.Add(credentialBlockDuration)
			source.expiresAt = source.blockedUntil
		}
	case credentialAccepted:
		if !now.Before(source.blockedUntil) {
			source.failures = nil
			source.expiresAt = now.Add(credentialFailureWindow)
		}
	case credentialUnavailable:
		// Transport failures consume the service budget, but are not bad guesses.
	}
}

func (s *credentialSource) expireFailures(now time.Time) {
	for len(s.failures) > 0 && !now.Before(s.failures[0].Add(credentialFailureWindow)) {
		s.failures = s.failures[1:]
	}
}

func (l *credentialLimiter) cleanup(now time.Time) {
	if now.Before(l.nextCleanup) {
		return
	}
	l.nextCleanup = now.Add(credentialCleanupInterval)
	for key, source := range l.sources {
		if source.pending == 0 && !now.Before(source.expiresAt) {
			delete(l.sources, key)
		}
	}
	for key, service := range l.services {
		if now.Sub(service.lastUsed) >= credentialBlockDuration {
			delete(l.services, key)
		}
	}
}
