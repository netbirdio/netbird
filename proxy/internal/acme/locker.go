package acme

import (
	"context"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/flock"
	"github.com/netbirdio/netbird/proxy/internal/k8s"
)

// certLocker provides distributed mutual exclusion for certificate operations.
// Implementations must be safe for concurrent use from multiple goroutines.
type certLocker interface {
	// Lock acquires an exclusive lock for the given domain.
	// It blocks until the lock is acquired, the context is cancelled, or an
	// unrecoverable error occurs. The returned function releases the lock;
	// callers must call it exactly once when the critical section is complete.
	Lock(ctx context.Context, domain string) (unlock func(), err error)
}

// CertLockMethod controls how ACME certificate locks are coordinated.
type CertLockMethod string

const (
	// CertLockAuto detects the environment and selects k8s-lease if running
	// in a Kubernetes pod, otherwise flock.
	CertLockAuto CertLockMethod = "auto"
	// CertLockFlock uses advisory file locks via flock(2).
	CertLockFlock CertLockMethod = "flock"
	// CertLockK8sLease uses Kubernetes coordination Leases.
	CertLockK8sLease CertLockMethod = "k8s-lease"
)

func newCertLocker(method CertLockMethod, certDir string, logger *log.Logger) certLocker {
	if logger == nil {
		logger = log.StandardLogger()
	}

	if method == "" || method == CertLockAuto {
		if k8s.InCluster() {
			method = CertLockK8sLease
		} else {
			method = CertLockFlock
		}
		logger.Infof("auto-detected cert lock method: %s", method)
	}

	switch method {
	case CertLockK8sLease:
		locker, err := newK8sLeaseLocker(logger)
		if err != nil {
			logger.Warnf("create k8s lease locker, falling back to flock: %v", err)
			return newFlockLocker(certDir, logger)
		}
		logger.Infof("using k8s lease locker in namespace %s", locker.client.Namespace())
		return locker
	default:
		logger.Infof("using flock cert locker in %s", certDir)
		return newFlockLocker(certDir, logger)
	}
}

type flockLocker struct {
	certDir string
	logger  *log.Logger
}

func newFlockLocker(certDir string, logger *log.Logger) *flockLocker {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &flockLocker{certDir: certDir, logger: logger}
}

// Lock acquires an advisory file lock for the given domain.
func (l *flockLocker) Lock(ctx context.Context, domain string) (func(), error) {
	lockPath := filepath.Join(l.certDir, domain+".lock")
	lockFile, err := flock.Lock(ctx, lockPath)
	if err != nil {
		return nil, err
	}

	// nil lockFile means locking is not supported (non-unix).
	if lockFile == nil {
		return func() { /* no-op: locking unsupported on this platform */ }, nil
	}

	return func() {
		if err := flock.Unlock(lockFile); err != nil {
			l.logger.Debugf("release cert lock for domain %q: %v", domain, err)
		}
	}, nil
}

type noopLocker struct{}

// Lock is a no-op that always succeeds immediately.
func (noopLocker) Lock(context.Context, string) (func(), error) {
	return func() { /* no-op: locker disabled */ }, nil
}
