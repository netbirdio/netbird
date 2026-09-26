package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetAccountOnboarding retrieves the onboarding information for a specific account.
func (s *SqlStore) GetAccountOnboarding(ctx context.Context, accountID string) (*types.AccountOnboarding, error) {
	var accountOnboarding types.AccountOnboarding
	result := s.db.Model(&accountOnboarding).Take(&accountOnboarding, accountIDCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountOnboardingNotFoundError(accountID)
		}
		log.WithContext(ctx).Errorf("error when getting account onboarding %s from the store: %s", accountID, result.Error)
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	return &accountOnboarding, nil
}

// SaveAccountOnboarding updates the onboarding information for a specific account.
func (s *SqlStore) SaveAccountOnboarding(ctx context.Context, onboarding *types.AccountOnboarding) error {
	result := s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(onboarding)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when saving account onboarding %s in the store: %s", onboarding.AccountID, result.Error)
		return status.Errorf(status.Internal, "error when saving account onboarding %s in the store: %s", onboarding.AccountID, result.Error)
	}

	return nil
}

func (s *SqlStore) getAccountOnboarding(ctx context.Context, accountID string, account *types.Account) error {
	const query = `SELECT account_id, onboarding_flow_pending, signup_form_pending, created_at, updated_at FROM account_onboardings WHERE account_id = $1`
	var onboardingFlowPending, signupFormPending sql.NullBool
	var createdAt, updatedAt sql.NullTime
	err := s.pool.QueryRow(ctx, query, accountID).Scan(
		&account.Onboarding.AccountID,
		&onboardingFlowPending,
		&signupFormPending,
		&createdAt,
		&updatedAt,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if createdAt.Valid {
		account.Onboarding.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		account.Onboarding.UpdatedAt = updatedAt.Time
	}
	if onboardingFlowPending.Valid {
		account.Onboarding.OnboardingFlowPending = onboardingFlowPending.Bool
	}
	if signupFormPending.Valid {
		account.Onboarding.SignupFormPending = signupFormPending.Bool
	}
	return nil
}
