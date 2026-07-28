package acme

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/k8s"
)

const (
	// leaseDurationSec is the Kubernetes Lease TTL. If the holder crashes without
	// releasing the lock, other replicas must wait this long before taking over.
	// This is intentionally generous: in the worst case two replicas may both
	// issue an ACME request for the same domain, which is harmless (the CA
	// deduplicates and the cache converges).
	leaseDurationSec = 300
	retryBaseBackoff = 500 * time.Millisecond
	retryMaxBackoff  = 10 * time.Second
)

type k8sLeaseLocker struct {
	client   *k8s.LeaseClient
	identity string
	logger   *log.Logger
}

func newK8sLeaseLocker(logger *log.Logger) (*k8sLeaseLocker, error) {
	client, err := k8s.NewLeaseClient()
	if err != nil {
		return nil, fmt.Errorf("create k8s lease client: %w", err)
	}

	identity, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}

	return &k8sLeaseLocker{
		client:   client,
		identity: identity,
		logger:   logger,
	}, nil
}

// Lock acquires a Kubernetes Lease for the given domain using optimistic
// concurrency. It retries with exponential backoff until the lease is
// acquired or the context is cancelled.
func (l *k8sLeaseLocker) Lock(ctx context.Context, domain string) (func(), error) {
	leaseName := k8s.LeaseNameForDomain(domain)
	backoff := retryBaseBackoff

	for {
		acquired, err := l.tryAcquire(ctx, leaseName, domain)
		if err != nil {
			return nil, fmt.Errorf("acquire lease %s for %q: %w", leaseName, domain, err)
		}
		if acquired {
			l.logger.Debugf("k8s lease %s acquired for domain %q", leaseName, domain)
			return l.unlockFunc(leaseName, domain), nil
		}

		l.logger.Debugf("k8s lease %s held by another replica, retrying in %s", leaseName, backoff)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}

		backoff *= 2
		if backoff > retryMaxBackoff {
			backoff = retryMaxBackoff
		}
	}
}

// tryAcquire attempts to create or take over a Lease. Returns (true, nil)
// on success, (false, nil) if the lease is held and not stale, or an error.
func (l *k8sLeaseLocker) tryAcquire(ctx context.Context, name, domain string) (bool, error) {
	existing, err := l.client.Get(ctx, name)
	if err != nil {
		return false, err
	}

	now := k8s.MicroTime{Time: time.Now().UTC()}
	dur := int32(leaseDurationSec)

	if existing == nil {
		lease := &k8s.Lease{
			Metadata: k8s.LeaseMetadata{
				Name: name,
				Annotations: map[string]string{
					"netbird.io/domain": domain,
				},
			},
			Spec: k8s.LeaseSpec{
				HolderIdentity:       &l.identity,
				LeaseDurationSeconds: &dur,
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}

		if _, err := l.client.Create(ctx, lease); errors.Is(err, k8s.ErrConflict) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		return true, nil
	}

	if !l.canTakeover(existing) {
		return false, nil
	}

	existing.Spec.HolderIdentity = &l.identity
	existing.Spec.LeaseDurationSeconds = &dur
	existing.Spec.AcquireTime = &now
	existing.Spec.RenewTime = &now

	if _, err := l.client.Update(ctx, existing); errors.Is(err, k8s.ErrConflict) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// canTakeover returns true if the lease is free (no holder) or stale
// (renewTime + leaseDuration has passed).
func (l *k8sLeaseLocker) canTakeover(lease *k8s.Lease) bool {
	holder := lease.Spec.HolderIdentity
	if holder == nil || *holder == "" {
		return true
	}

	// We already hold it (e.g. from a previous crashed attempt).
	if *holder == l.identity {
		return true
	}

	if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return true
	}

	expiry := lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second)
	if time.Now().After(expiry) {
		l.logger.Infof("k8s lease %s held by %q is stale (expired %s ago), taking over",
			lease.Metadata.Name, *holder, time.Since(expiry).Round(time.Second))
		return true
	}

	return false
}

// unlockFunc returns a closure that releases the lease by clearing the holder.
func (l *k8sLeaseLocker) unlockFunc(name, domain string) func() {
	return func() {
		// Use a fresh context: the parent may already be cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Re-GET to get current resourceVersion (ours may be stale if
		// the lock was held for a long time and something updated it).
		current, err := l.client.Get(ctx, name)
		if err != nil {
			l.logger.Debugf("release k8s lease %s for %q: get: %v", name, domain, err)
			return
		}
		if current == nil {
			return
		}

		// Only clear if we're still the holder.
		if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != l.identity {
			l.logger.Debugf("k8s lease %s for %q: holder changed to %v, skip release",
				name, domain, current.Spec.HolderIdentity)
			return
		}

		empty := ""
		current.Spec.HolderIdentity = &empty
		current.Spec.AcquireTime = nil
		current.Spec.RenewTime = nil

		if _, err := l.client.Update(ctx, current); err != nil {
			l.logger.Debugf("release k8s lease %s for %q: update: %v", name, domain, err)
		}
	}
}
