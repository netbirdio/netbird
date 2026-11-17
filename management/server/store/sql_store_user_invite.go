package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// SaveUserInvite saves a user invite to the database
func (s *SqlStore) SaveUserInvite(ctx context.Context, invite *types.UserInviteRecord) error {
	inviteCopy := invite.Copy()
	if err := inviteCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt invite: %w", err)
	}

	result := s.db.Save(inviteCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save user invite to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save user invite to store")
	}
	return nil
}

// GetUserInviteByID retrieves a user invite by its ID and account ID
func (s *SqlStore) GetUserInviteByID(ctx context.Context, lockStrength LockingStrength, accountID, inviteID string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invite types.UserInviteRecord
	result := tx.Where("account_id = ?", accountID).Take(&invite, idQueryCondition, inviteID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "user invite not found")
		}
		log.WithContext(ctx).Errorf("failed to get user invite from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invite from store")
	}

	if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt invite: %w", err)
	}

	return &invite, nil
}

// GetUserInviteByHashedToken retrieves a user invite by its hashed token
func (s *SqlStore) GetUserInviteByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invite types.UserInviteRecord
	result := tx.Take(&invite, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "user invite not found")
		}
		log.WithContext(ctx).Errorf("failed to get user invite from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invite from store")
	}

	if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt invite: %w", err)
	}

	return &invite, nil
}

// GetUserInviteByEmail retrieves a user invite by account ID and email.
// Since email is encrypted with random IVs, we fetch all invites for the account
// and compare emails in memory after decryption.
func (s *SqlStore) GetUserInviteByEmail(ctx context.Context, lockStrength LockingStrength, accountID, email string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invites []*types.UserInviteRecord
	result := tx.Find(&invites, "account_id = ?", accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get user invites from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invites from store")
	}

	for _, invite := range invites {
		if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt invite: %w", err)
		}
		if strings.EqualFold(invite.Email, email) {
			return invite, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "user invite not found for email")
}

// GetAccountUserInvites retrieves all user invites for an account
func (s *SqlStore) GetAccountUserInvites(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invites []*types.UserInviteRecord
	result := tx.Find(&invites, "account_id = ?", accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get user invites from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invites from store")
	}

	for _, invite := range invites {
		if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt invite: %w", err)
		}
	}

	return invites, nil
}

// DeleteUserInvite deletes a user invite by its ID
func (s *SqlStore) DeleteUserInvite(ctx context.Context, inviteID string) error {
	result := s.db.Delete(&types.UserInviteRecord{}, idQueryCondition, inviteID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete user invite from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete user invite from store")
	}
	return nil
}
