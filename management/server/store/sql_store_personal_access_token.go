package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// DeleteHashedPAT2TokenIDIndex is noop in SqlStore
func (s *SqlStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	return nil
}

// DeleteTokenID2UserIDIndex is noop in SqlStore
func (s *SqlStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	return nil
}

func (s *SqlStore) GetTokenIDByHashedToken(ctx context.Context, hashedToken string) (string, error) {
	var token types.PersonalAccessToken
	result := s.db.Take(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting token from the store: %s", result.Error)
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return token.ID, nil
}

func (s *SqlStore) getPersonalAccessTokens(ctx context.Context, userIDs []string) ([]types.PersonalAccessToken, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	const query = `SELECT id, user_id, name, hashed_token, expiration_date, created_by, created_at, last_used FROM personal_access_tokens WHERE user_id = ANY($1)`
	rows, err := s.pool.Query(ctx, query, userIDs)
	if err != nil {
		return nil, err
	}
	pats, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.PersonalAccessToken, error) {
		var pat types.PersonalAccessToken
		var expirationDate, lastUsed, createdAt sql.NullTime
		err := row.Scan(&pat.ID, &pat.UserID, &pat.Name, &pat.HashedToken, &expirationDate, &pat.CreatedBy, &createdAt, &lastUsed)
		if err == nil {
			if expirationDate.Valid {
				pat.ExpirationDate = &expirationDate.Time
			}
			if createdAt.Valid {
				pat.CreatedAt = createdAt.Time
			}
			if lastUsed.Valid {
				pat.LastUsed = &lastUsed.Time
			}
		}
		return pat, err
	})
	if err != nil {
		return nil, err
	}
	return pats, nil
}

// GetPATByHashedToken returns a PersonalAccessToken by its hashed token.
func (s *SqlStore) GetPATByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken string) (*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pat types.PersonalAccessToken
	result := tx.Take(&pat, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPATNotFoundError(hashedToken)
		}
		log.WithContext(ctx).Errorf("failed to get pat by hash from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get pat by hash from store")
	}

	return &pat, nil
}

// GetPATByID retrieves a personal access token by its ID and user ID.
func (s *SqlStore) GetPATByID(ctx context.Context, lockStrength LockingStrength, userID string, patID string) (*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pat types.PersonalAccessToken
	result := tx.
		Take(&pat, "id = ? AND user_id = ?", patID, userID)
	if err := result.Error; err != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPATNotFoundError(patID)
		}
		log.WithContext(ctx).Errorf("failed to get pat from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get pat from store")
	}

	return &pat, nil
}

// GetUserPATs retrieves personal access tokens for a user.
func (s *SqlStore) GetUserPATs(ctx context.Context, lockStrength LockingStrength, userID string) ([]*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pats []*types.PersonalAccessToken
	result := tx.Find(&pats, "user_id = ?", userID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get user pat's from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get user pat's from store")
	}

	return pats, nil
}

// MarkPATUsed marks a personal access token as used.
func (s *SqlStore) MarkPATUsed(ctx context.Context, patID string) error {
	patCopy := types.PersonalAccessToken{
		LastUsed: util.ToPtr(time.Now().UTC()),
	}

	fieldsToUpdate := []string{"last_used"}
	result := s.db.Select(fieldsToUpdate).
		Where(idQueryCondition, patID).Updates(&patCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pat as used: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pat as used")
	}

	if result.RowsAffected == 0 {
		return status.NewPATNotFoundError(patID)
	}

	return nil
}

// SavePAT saves a personal access token to the database.
func (s *SqlStore) SavePAT(ctx context.Context, pat *types.PersonalAccessToken) error {
	result := s.db.Save(pat)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save pat to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save pat to store")
	}

	return nil
}

// DeletePAT deletes a personal access token from the database.
func (s *SqlStore) DeletePAT(ctx context.Context, userID, patID string) error {
	result := s.db.Delete(&types.PersonalAccessToken{}, "user_id = ? AND id = ?", userID, patID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete pat from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete pat from store")
	}

	if result.RowsAffected == 0 {
		return status.NewPATNotFoundError(patID)
	}

	return nil
}
