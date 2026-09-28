package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getPolicies(ctx context.Context, accountID string) ([]*types.Policy, error) {
	const query = `SELECT id, account_id, public_id, name, description, enabled, source_posture_checks FROM policies WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Policy, error) {
		var p types.Policy
		var checks []byte
		var enabled sql.NullBool
		err := row.Scan(&p.ID, &p.AccountID, &p.PublicID, &p.Name, &p.Description, &enabled, &checks)
		if err == nil {
			if enabled.Valid {
				p.Enabled = enabled.Bool
			}
			if checks != nil {
				_ = json.Unmarshal(checks, &p.SourcePostureChecks)
			}
		}
		return &p, err
	})
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// GetAccountPolicies retrieves policies for an account.
func (s *SqlStore) GetAccountPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policies []*types.Policy
	result := tx.
		Preload(clause.Associations).Find(&policies, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get policies from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get policies from store")
	}

	return policies, nil
}

// GetPolicyByID retrieves a policy by its ID and account ID.
func (s *SqlStore) GetPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*types.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policy *types.Policy

	result := tx.Preload(clause.Associations).
		Take(&policy, accountAndIDQueryCondition, accountID, policyID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewPolicyNotFoundError(policyID)
		}
		log.WithContext(ctx).Errorf("failed to get policy from store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get policy from store")
	}

	return policy, nil
}

// GetPolicyByIDOrPublicID retrieves a policy by either its ID or its PublicID. Peers report
// whichever of the two the network map they were served carries, so callers resolving a
// peer-reported reference cannot know upfront which namespace it belongs to.
func (s *SqlStore) GetPolicyByIDOrPublicID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*types.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policy *types.Policy

	result := tx.Preload(clause.Associations).
		Take(&policy, accountAndAnyIDQueryCondition, accountID, policyID, policyID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewPolicyNotFoundError(policyID)
		}
		log.WithContext(ctx).Errorf("failed to get policy from store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get policy from store")
	}

	return policy, nil
}

func (s *SqlStore) CreatePolicy(ctx context.Context, policy *types.Policy) error {
	result := s.db.Create(policy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create policy in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to create policy in store")
	}

	return nil
}

// SavePolicy saves a policy to the database.
func (s *SqlStore) SavePolicy(ctx context.Context, policy *types.Policy) error {
	result := s.db.Session(&gorm.Session{FullSaveAssociations: true}).Omit("public_id").Save(policy)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save policy to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save policy to store")
	}
	return nil
}

func (s *SqlStore) DeletePolicy(ctx context.Context, accountID, policyID string) error {
	return s.transaction(func(tx *gorm.DB) error {
		if err := tx.Where("policy_id = ?", policyID).Delete(&types.PolicyRule{}).Error; err != nil {
			return fmt.Errorf("delete policy rules: %w", err)
		}

		result := tx.
			Where(accountAndIDQueryCondition, accountID, policyID).
			Delete(&types.Policy{})

		if err := result.Error; err != nil {
			log.WithContext(ctx).Errorf("failed to delete policy from store: %s", err)
			return status.Errorf(status.Internal, "failed to delete policy from store")
		}

		if result.RowsAffected == 0 {
			return status.NewPolicyNotFoundError(policyID)
		}

		return nil
	})
}
