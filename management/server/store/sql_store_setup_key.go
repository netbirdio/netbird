package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) GetAccountBySetupKey(ctx context.Context, setupKey string) (*types.Account, error) {
	var key types.SetupKey
	result := s.db.Select("account_id").Take(&key, GetKeyQueryCondition(s), setupKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewSetupKeyNotFoundError(setupKey)
		}
		log.WithContext(ctx).Errorf("failed to get account by setup key from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get account by setup key from store")
	}

	if key.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, key.AccountID)
}

func (s *SqlStore) getSetupKeys(ctx context.Context, accountID string) ([]types.SetupKey, error) {
	const query = `SELECT id, account_id, key, key_secret, name, type, created_at, expires_at, updated_at, 
	revoked, used_times, last_used, auto_groups, usage_limit, ephemeral, allow_extra_dns_labels FROM setup_keys WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}

	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.SetupKey, error) {
		var sk types.SetupKey
		var autoGroups []byte
		var skCreatedAt, expiresAt, updatedAt, lastUsed sql.NullTime
		var revoked, ephemeral, allowExtraDNSLabels sql.NullBool
		var usedTimes, usageLimit sql.NullInt64

		err := row.Scan(&sk.Id, &sk.AccountID, &sk.Key, &sk.KeySecret, &sk.Name, &sk.Type, &skCreatedAt,
			&expiresAt, &updatedAt, &revoked, &usedTimes, &lastUsed, &autoGroups, &usageLimit, &ephemeral, &allowExtraDNSLabels)

		if err == nil {
			if expiresAt.Valid {
				sk.ExpiresAt = &expiresAt.Time
			}
			if skCreatedAt.Valid {
				sk.CreatedAt = skCreatedAt.Time
			}
			if updatedAt.Valid {
				sk.UpdatedAt = updatedAt.Time
				if sk.UpdatedAt.IsZero() {
					sk.UpdatedAt = sk.CreatedAt
				}
			}
			if lastUsed.Valid {
				sk.LastUsed = &lastUsed.Time
			}
			if revoked.Valid {
				sk.Revoked = revoked.Bool
			}
			if usedTimes.Valid {
				sk.UsedTimes = int(usedTimes.Int64)
			}
			if usageLimit.Valid {
				sk.UsageLimit = int(usageLimit.Int64)
			}
			if ephemeral.Valid {
				sk.Ephemeral = ephemeral.Bool
			}
			if allowExtraDNSLabels.Valid {
				sk.AllowExtraDNSLabels = allowExtraDNSLabels.Bool
			}
			if autoGroups != nil {
				_ = json.Unmarshal(autoGroups, &sk.AutoGroups)
			} else {
				sk.AutoGroups = []string{}
			}
		}
		return sk, err
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *SqlStore) GetAccountIDBySetupKey(ctx context.Context, setupKey string) (string, error) {
	var accountID string
	result := s.db.Model(&types.SetupKey{}).Select("account_id").Where(GetKeyQueryCondition(s), setupKey).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.NewSetupKeyNotFoundError(setupKey)
		}
		log.WithContext(ctx).Errorf("failed to get account ID by setup key from store: %v", result.Error)
		return "", status.Errorf(status.Internal, "failed to get account ID by setup key from store")
	}

	if accountID == "" {
		return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return accountID, nil
}

func (s *SqlStore) GetSetupKeyBySecret(ctx context.Context, lockStrength LockingStrength, key string) (*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKey types.SetupKey
	result := tx.
		Take(&setupKey, GetKeyQueryCondition(s), key)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.PreconditionFailed, "setup key not found")
		}
		log.WithContext(ctx).Errorf("failed to get setup key by secret from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get setup key by secret from store")
	}
	return &setupKey, nil
}

func (s *SqlStore) IncrementSetupKeyUsage(ctx context.Context, setupKeyID string) error {
	result := s.db.Model(&types.SetupKey{}).
		Where(idQueryCondition, setupKeyID).
		Updates(map[string]interface{}{
			"used_times": gorm.Expr("used_times + 1"),
			"last_used":  time.Now(),
		})

	if result.Error != nil {
		return status.Errorf(status.Internal, "issue incrementing setup key usage count: %s", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.NewSetupKeyNotFoundError(setupKeyID)
	}

	return nil
}

// GetAccountSetupKeys retrieves setup keys for an account.
func (s *SqlStore) GetAccountSetupKeys(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKeys []*types.SetupKey
	result := tx.
		Find(&setupKeys, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get setup keys from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get setup keys from store")
	}

	return setupKeys, nil
}

// GetSetupKeyByID retrieves a setup key by its ID and account ID.
func (s *SqlStore) GetSetupKeyByID(ctx context.Context, lockStrength LockingStrength, accountID, setupKeyID string) (*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKey *types.SetupKey
	result := tx.Take(&setupKey, accountAndIDQueryCondition, accountID, setupKeyID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewSetupKeyNotFoundError(setupKeyID)
		}
		log.WithContext(ctx).Errorf("failed to get setup key from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get setup key from store")
	}

	return setupKey, nil
}

// SaveSetupKey saves a setup key to the database.
func (s *SqlStore) SaveSetupKey(ctx context.Context, setupKey *types.SetupKey) error {
	result := s.db.Save(setupKey)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save setup key to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save setup key to store")
	}

	return nil
}

// DeleteSetupKey deletes a setup key from the database.
func (s *SqlStore) DeleteSetupKey(ctx context.Context, accountID, keyID string) error {
	result := s.db.Delete(&types.SetupKey{}, accountAndIDQueryCondition, accountID, keyID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete setup key from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete setup key from store")
	}

	if result.RowsAffected == 0 {
		return status.NewSetupKeyNotFoundError(keyID)
	}

	return nil
}
