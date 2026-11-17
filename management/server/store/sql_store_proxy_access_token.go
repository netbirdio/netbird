package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetProxyAccessTokenByHashedToken retrieves a proxy access token by its hashed value.
func (s *SqlStore) GetProxyAccessTokenByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken types.HashedProxyToken) (*types.ProxyAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var token types.ProxyAccessToken
	result := tx.Take(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "proxy access token not found")
		}
		return nil, status.Errorf(status.Internal, "get proxy access token: %v", result.Error)
	}

	return &token, nil
}

// GetAllProxyAccessTokens retrieves all proxy access tokens.
func (s *SqlStore) GetAllProxyAccessTokens(ctx context.Context, lockStrength LockingStrength) ([]*types.ProxyAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var tokens []*types.ProxyAccessToken
	result := tx.Find(&tokens)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "get proxy access tokens: %v", result.Error)
	}

	return tokens, nil
}

// SaveProxyAccessToken saves a proxy access token to the database.
func (s *SqlStore) SaveProxyAccessToken(ctx context.Context, token *types.ProxyAccessToken) error {
	if result := s.db.Create(token); result.Error != nil {
		return status.Errorf(status.Internal, "save proxy access token: %v", result.Error)
	}
	return nil
}

// RevokeProxyAccessToken revokes a proxy access token by its ID.
func (s *SqlStore) RevokeProxyAccessToken(ctx context.Context, tokenID string) error {
	result := s.db.Model(&types.ProxyAccessToken{}).Where(idQueryCondition, tokenID).Update("revoked", true)
	if result.Error != nil {
		return status.Errorf(status.Internal, "revoke proxy access token: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "proxy access token not found")
	}

	return nil
}

func (s *SqlStore) GetProxyAccessTokensByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.ProxyAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var tokens []*types.ProxyAccessToken
	result := tx.Where("account_id = ?", accountID).Find(&tokens)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "get proxy access tokens by account: %v", result.Error)
	}

	return tokens, nil
}

func (s *SqlStore) IsProxyAccessTokenValid(ctx context.Context, tokenID string) (bool, error) {
	token, err := s.GetProxyAccessTokenByID(ctx, LockingStrengthNone, tokenID)
	if err != nil {
		return false, err
	}
	return token.IsValid(), nil
}

func (s *SqlStore) GetProxyAccessTokenByID(ctx context.Context, lockStrength LockingStrength, tokenID string) (*types.ProxyAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var token types.ProxyAccessToken
	result := tx.Take(&token, idQueryCondition, tokenID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "proxy access token not found")
		}
		return nil, status.Errorf(status.Internal, "get proxy access token by ID: %v", result.Error)
	}

	return &token, nil
}

// MarkProxyAccessTokenUsed updates the last used timestamp for a proxy access token.
func (s *SqlStore) MarkProxyAccessTokenUsed(ctx context.Context, tokenID string) error {
	result := s.db.Model(&types.ProxyAccessToken{}).
		Where(idQueryCondition, tokenID).
		Update("last_used", time.Now().UTC())
	if result.Error != nil {
		return status.Errorf(status.Internal, "mark proxy access token as used: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "proxy access token not found")
	}

	return nil
}
