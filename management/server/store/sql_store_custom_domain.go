package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetCustomDomainsCounts returns the total and validated custom domain counts.
func (s *SqlStore) GetCustomDomainsCounts(ctx context.Context) (int64, int64, error) {
	var total, validated int64
	if err := s.db.Model(&domain.Domain{}).Count(&total).Error; err != nil {
		return 0, 0, err
	}
	if err := s.db.Model(&domain.Domain{}).Where("validated = ?", true).Count(&validated).Error; err != nil {
		return 0, 0, err
	}
	return total, validated, nil
}

func (s *SqlStore) GetCustomDomain(ctx context.Context, accountID string, domainID string) (*domain.Domain, error) {
	tx := s.db

	customDomain := &domain.Domain{}
	result := tx.Take(&customDomain, accountAndIDQueryCondition, accountID, domainID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "custom domain %s not found", domainID)
		}

		log.WithContext(ctx).Errorf("failed to get custom domain from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get custom domain from store")
	}

	return customDomain, nil
}

func (s *SqlStore) ListFreeDomains(ctx context.Context, accountID string) ([]string, error) {
	return nil, nil
}

func (s *SqlStore) ListCustomDomains(ctx context.Context, accountID string) ([]*domain.Domain, error) {
	tx := s.db

	var domains []*domain.Domain
	result := tx.Find(&domains, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get reverse proxy custom domains from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get reverse proxy custom domains from store")
	}

	return domains, nil
}

// GetCustomDomainByName returns the custom domain row holding the given name,
// regardless of which account owns it.
func (s *SqlStore) GetCustomDomainByName(ctx context.Context, domainName string) (*domain.Domain, error) {
	customDomain := &domain.Domain{}
	result := s.db.Take(customDomain, "domain = ?", domainName)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "custom domain %s not found", domainName)
		}

		log.WithContext(ctx).Errorf("failed to get custom domain by name from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get custom domain from store")
	}

	return customDomain, nil
}

func (s *SqlStore) CreateCustomDomain(ctx context.Context, accountID string, domainName string, targetCluster string, validated bool) (*domain.Domain, error) {
	newDomain := &domain.Domain{
		ID:            xid.New().String(), // Generate our own ID because gorm doesn't always configure the database to handle this for us.
		Domain:        domainName,
		AccountID:     accountID,
		TargetCluster: targetCluster,
		Type:          domain.TypeCustom,
		Validated:     validated,
	}
	if !validated {
		expiresAt := time.Now().UTC().Add(domain.ValidationTTL)
		newDomain.ValidationExpiresAt = &expiresAt
	}
	result := s.db.Create(newDomain)
	if result.Error != nil {
		// The unique index is the last guard when two requests clear the
		// manager's availability check at the same time. The one that loses the
		// insert is a conflict, not an internal failure.
		var count int64
		if err := s.db.Model(&domain.Domain{}).Where("domain = ?", domainName).Count(&count).Error; err == nil && count > 0 {
			// The insert error is logged even on this path: the name being taken
			// is what the caller has to act on, but if the insert also failed for
			// an unrelated reason the operator still needs to see it.
			log.WithContext(ctx).Warnf("create reverse proxy custom domain %s rejected, name already registered: %v", domainName, result.Error)
			return nil, status.Errorf(status.AlreadyExists, "domain %s is already registered", domainName)
		}

		log.WithContext(ctx).Errorf("failed to create reverse proxy custom domain to store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to create reverse proxy custom domain to store")
	}

	return newDomain, nil
}

// UpdateCustomDomain completes validation only while the original registration is pending.
func (s *SqlStore) UpdateCustomDomain(ctx context.Context, accountID string, d *domain.Domain) (*domain.Domain, error) {
	if !d.Validated {
		return nil, status.Errorf(status.InvalidArgument, "custom domain update must complete validation")
	}
	result := s.db.WithContext(ctx).Model(&domain.Domain{}).
		Where(accountAndIDQueryCondition, accountID, d.ID).
		Where("domain = ? AND target_cluster = ?", d.Domain, d.TargetCluster).
		Where("validated = ? AND validation_expires_at > ?", false, time.Now().UTC()).
		Update("validated", true)
	if result.Error != nil {
		return nil, fmt.Errorf("validate custom domain in store: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, status.Errorf(status.PreconditionFailed, "custom domain registration is no longer pending validation")
	}

	return d, nil
}

func (s *SqlStore) DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error {
	result := s.db.Delete(domain.Domain{}, accountAndIDQueryCondition, accountID, domainID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete reverse proxy custom domain from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete reverse proxy custom domain from store")
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "reverse proxy custom domain %s not found", domainID)
	}

	return nil
}
