package grpc

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	credentialVerificationInterval        = 6 * time.Second
	credentialVerificationBurst           = 5
	credentialVerificationMaxServices     = 4096
	credentialVerificationIdleTimeout     = 15 * time.Minute
	credentialVerificationCleanupInterval = time.Minute
)

type credentialAccountID string
type credentialServiceID string

type credentialVerificationKey struct {
	accountID credentialAccountID
	serviceID credentialServiceID
}

type credentialVerificationBudget struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// The zero value is ready to use. Budgets are local to this Management process;
// proxy replicas reaching this process share a service's verification budget.
type credentialVerificationLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	services    map[credentialVerificationKey]*credentialVerificationBudget
	nextCleanup time.Time
	closed      bool
}

func (l *credentialVerificationLimiter) allow(key credentialVerificationKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return status.Error(codes.Unavailable, "credential verification is closed")
	}
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	l.cleanup(now)
	budget := l.services[key]
	if budget == nil {
		if len(l.services) >= credentialVerificationMaxServices {
			return credentialVerificationThrottled(credentialVerificationCleanupInterval)
		}
		if l.services == nil {
			l.services = make(map[credentialVerificationKey]*credentialVerificationBudget)
		}
		budget = &credentialVerificationBudget{limiter: rate.NewLimiter(rate.Every(credentialVerificationInterval), credentialVerificationBurst)}
		l.services[key] = budget
	}
	budget.lastUsed = now
	if budget.limiter.AllowN(now, 1) {
		return nil
	}
	delay := max(time.Nanosecond, time.Duration((1-budget.limiter.TokensAt(now))*float64(credentialVerificationInterval)))
	return credentialVerificationThrottled(delay)
}

func (l *credentialVerificationLimiter) cleanup(now time.Time) {
	if now.Before(l.nextCleanup) {
		return
	}
	l.nextCleanup = now.Add(credentialVerificationCleanupInterval)
	for key, budget := range l.services {
		if now.Sub(budget.lastUsed) >= credentialVerificationIdleTimeout {
			delete(l.services, key)
		}
	}
}

func (l *credentialVerificationLimiter) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.services = nil
}

func credentialVerificationThrottled(delay time.Duration) error {
	s := status.New(codes.ResourceExhausted, "too many credential verification attempts")
	withRetry, err := s.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(delay)})
	if err != nil {
		return s.Err()
	}
	return withRetry.Err()
}
