package migration

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
)

// MigrateCustomDomainValidationExpiry gives existing pending registrations a validation window.
func MigrateCustomDomainValidationExpiry(ctx context.Context, db *gorm.DB) error {
	result := db.WithContext(ctx).Model(&domain.Domain{}).
		Where("validated = ? AND validation_expires_at IS NULL", false).
		Update("validation_expires_at", time.Now().UTC().Add(domain.ValidationTTL))
	if result.Error != nil {
		return fmt.Errorf("backfill custom domain validation expiry: %w", result.Error)
	}
	return nil
}
