package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetExpiredCustomDomains lists pending registrations in stable batches across accounts.
func (s *SqlStore) GetExpiredCustomDomains(ctx context.Context, now time.Time, afterID domain.ID, limit int) ([]*domain.Domain, error) {
	var domains []*domain.Domain
	result := s.db.WithContext(ctx).
		Where("validated = ? AND validation_expires_at <= ? AND id > ?", false, now, string(afterID)).
		Order("id").Limit(limit).Find(&domains)
	if result.Error != nil {
		return nil, fmt.Errorf("list expired custom domains: %w", result.Error)
	}
	return domains, nil
}

// DeleteExpiredCustomDomain deletes an expired registration only if no service uses its namespace.
func (s *SqlStore) DeleteExpiredCustomDomain(ctx context.Context, d *domain.Domain, now time.Time) (bool, error) {
	db := s.db.WithContext(ctx)
	services := customDomainServices(db, d)
	result := db.Where(accountAndIDQueryCondition, d.AccountID, d.ID).
		Where("domain = ? AND validated = ? AND validation_expires_at <= ?", d.Domain, false, now).
		Where("NOT EXISTS (?)", services.Select("1")).Delete(&domain.Domain{})
	if result.Error != nil {
		return false, fmt.Errorf("delete expired custom domain: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		return true, nil
	}
	var count int64
	if err := customDomainServices(db, d).Count(&count).Error; err != nil {
		return false, fmt.Errorf("check expired custom domain services: %w", err)
	}
	if count > 0 {
		return false, status.Errorf(status.PreconditionFailed, "expired custom domain still has dependent services")
	}
	return false, nil
}

func customDomainServices(db *gorm.DB, d *domain.Domain) *gorm.DB {
	name := strings.ToLower(strings.TrimSuffix(d.Domain, "."))
	escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(name)
	return db.Model(&rpservice.Service{}).Where(
		"LOWER(domain) IN ? OR LOWER(domain) LIKE ? ESCAPE '!' OR LOWER(domain) LIKE ? ESCAPE '!'",
		[]string{name, name + "."}, "%."+escaped, "%."+escaped+".",
	)
}
