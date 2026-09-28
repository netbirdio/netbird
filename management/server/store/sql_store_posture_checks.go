package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getPostureChecks(ctx context.Context, accountID string) ([]*posture.Checks, error) {
	const query = `SELECT id, account_id, public_id, name, description, checks FROM posture_checks WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	checks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*posture.Checks, error) {
		var c posture.Checks
		var checksDef []byte
		err := row.Scan(&c.ID, &c.AccountID, &c.PublicID, &c.Name, &c.Description, &checksDef)
		if err == nil && checksDef != nil {
			_ = json.Unmarshal(checksDef, &c.Checks)
		}
		return &c, err
	})
	if err != nil {
		return nil, err
	}
	return checks, nil
}

func (s *SqlStore) GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	definitionJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, err
	}

	var postureCheck posture.Checks
	err = s.db.Where("account_id = ? AND checks = ?", accountID, string(definitionJSON)).Take(&postureCheck).Error
	if err != nil {
		return nil, err
	}

	return &postureCheck, nil
}

// GetAccountPostureChecks retrieves posture checks for an account.
func (s *SqlStore) GetAccountPostureChecks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureChecks []*posture.Checks
	result := tx.Find(&postureChecks, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get posture checks from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture checks from store")
	}

	return postureChecks, nil
}

// GetPostureChecksByID retrieves posture checks by their ID and account ID.
func (s *SqlStore) GetPostureChecksByID(ctx context.Context, lockStrength LockingStrength, accountID, postureChecksID string) (*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureCheck *posture.Checks
	result := tx.
		Take(&postureCheck, accountAndIDQueryCondition, accountID, postureChecksID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPostureChecksNotFoundError(postureChecksID)
		}
		log.WithContext(ctx).Errorf("failed to get posture check from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture check from store")
	}

	return postureCheck, nil
}

// GetPostureChecksByIDs retrieves posture checks by their IDs and account ID.
func (s *SqlStore) GetPostureChecksByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, postureChecksIDs []string) (map[string]*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureChecks []*posture.Checks
	result := tx.Find(&postureChecks, accountAndIDsQueryCondition, accountID, postureChecksIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get posture checks by ID's from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture checks by ID's from store")
	}

	postureChecksMap := make(map[string]*posture.Checks)
	for _, postureCheck := range postureChecks {
		postureChecksMap[postureCheck.ID] = postureCheck
	}

	return postureChecksMap, nil
}

// SavePostureChecks saves a posture checks to the database.
func (s *SqlStore) SavePostureChecks(ctx context.Context, postureCheck *posture.Checks) error {
	result := s.db.Save(postureCheck)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save posture checks to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save posture checks to store")
	}

	return nil
}

// DeletePostureChecks deletes a posture checks from the database.
func (s *SqlStore) DeletePostureChecks(ctx context.Context, accountID, postureChecksID string) error {
	result := s.db.Delete(&posture.Checks{}, accountAndIDQueryCondition, accountID, postureChecksID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete posture checks from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete posture checks from store")
	}

	if result.RowsAffected == 0 {
		return status.NewPostureChecksNotFoundError(postureChecksID)
	}

	return nil
}
