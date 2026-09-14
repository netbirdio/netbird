package manager

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/server/activity"
)

const (
	validationCleanupInterval = 60 * time.Minute
	validationCleanupBatch    = 100
)

// RunValidationCleanup removes expired registrations on startup and hourly until cancellation.
func (m Manager) RunValidationCleanup(ctx context.Context) {
	ticker := time.NewTicker(validationCleanupInterval)
	defer ticker.Stop()
	for {
		m.cleanupExpiredDomains(ctx, time.Now().UTC())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m Manager) cleanupExpiredDomains(ctx context.Context, now time.Time) {
	var afterID domain.ID
	for ctx.Err() == nil {
		domains, err := m.store.GetExpiredCustomDomains(ctx, now, afterID, validationCleanupBatch)
		if err != nil {
			if ctx.Err() == nil {
				log.WithContext(ctx).WithError(err).Error("list expired custom domain registrations")
			}
			return
		}
		for _, d := range domains {
			if ctx.Err() != nil {
				return
			}
			m.deleteExpiredDomain(ctx, d, now)
			afterID = domain.ID(d.ID)
		}
		if len(domains) < validationCleanupBatch {
			return
		}
	}
}

func (m Manager) deleteExpiredDomain(ctx context.Context, d *domain.Domain, now time.Time) {
	deleted, err := m.store.DeleteExpiredCustomDomain(ctx, d, now)
	if err != nil {
		if ctx.Err() == nil {
			log.WithContext(ctx).WithFields(log.Fields{"accountID": d.AccountID, "domainID": d.ID}).
				WithError(err).Warn("could not expire custom domain registration")
		}
		return
	}
	if !deleted {
		return
	}
	meta := d.EventMeta()
	if d.ValidationExpiresAt != nil {
		meta["validation_expires_at"] = d.ValidationExpiresAt.UTC().Format(time.RFC3339)
	}
	m.accountManager.StoreEvent(ctx, activity.SystemInitiator, d.ID, d.AccountID,
		activity.CustomDomainValidationExpired, meta)
}
