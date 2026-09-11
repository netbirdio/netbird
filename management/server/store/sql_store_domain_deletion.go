package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

// LockCustomDomains locks an account's registrations until the caller's transaction ends.
func (s *SqlStore) LockCustomDomains(ctx context.Context, accountID string) ([]*domain.Domain, error) {
	var domains []*domain.Domain
	if err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: string(LockingStrengthUpdate)}).
		Where(accountIDCondition, accountID).Order("id").Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("lock custom domains: %w", err)
	}
	return domains, nil
}

// DeleteCustomDomain removes a registration only when no service uses its namespace.
func (s *SqlStore) DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var d domain.Domain
		// Service writes take the same lock before checking validation, so neither
		// operation can commit against the other's outdated view of the domain.
		if err := tx.Clauses(clause.Locking{Strength: string(LockingStrengthUpdate)}).
			Take(&d, accountAndIDQueryCondition, accountID, domainID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return status.Errorf(status.NotFound, "custom domain not found")
			}
			return fmt.Errorf("lock custom domain for deletion: %w", err)
		}

		result := tx.Where(accountAndIDQueryCondition, accountID, domainID).
			Where("NOT EXISTS (?)", customDomainServices(tx, &d).Select("1")).Delete(&domain.Domain{})
		if result.Error != nil {
			return fmt.Errorf("delete custom domain: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return status.Errorf(status.PreconditionFailed, "custom domain has dependent services; delete or move them before deleting the domain")
		}
		return nil
	})
}
