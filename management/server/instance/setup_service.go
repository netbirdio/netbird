package instance

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/auth"
)

const setupPATTokenName = "setup-token"

// SetupOptions controls optional work performed during initial instance setup.
type SetupOptions struct {
	CreatePAT       bool
	PATExpireInDays int
}

// SetupResult contains resources created during initial instance setup.
type SetupResult struct {
	User          *idp.UserData
	PATPlainToken string
}

// SetupService orchestrates the initial setup use case across the instance and
// account bounded contexts and owns the compensation logic when a later step
// fails.
type SetupService struct {
	instanceManager Manager
	accountManager  account.Manager
}

// NewSetupService creates a setup use-case service.
func NewSetupService(instanceManager Manager, accountManager account.Manager) *SetupService {
	return &SetupService{
		instanceManager: instanceManager,
		accountManager:  accountManager,
	}
}

// SetupOwner creates the initial owner user and, optionally, provisions the
// account and a setup Personal Access Token. If account or PAT provisioning
// fails, created resources are rolled back so setup can be retried.
func (m *SetupService) SetupOwner(ctx context.Context, email, password, name string, opts SetupOptions) (*SetupResult, error) {
	userData, err := m.instanceManager.CreateOwnerUser(ctx, email, password, name)
	if err != nil {
		return nil, err
	}

	result := &SetupResult{User: userData}
	if !opts.CreatePAT {
		return result, nil
	}

	if m.accountManager == nil {
		err := fmt.Errorf("account manager is required to create setup PAT")
		m.rollbackSetup(ctx, userData.ID, "setup PAT requested without account manager", err, "")
		return nil, err
	}

	userAuth := auth.UserAuth{
		UserId: userData.ID,
		Email:  userData.Email,
		Name:   userData.Name,
	}

	accountID, err := m.accountManager.GetAccountIDByUserID(ctx, userAuth)
	if err != nil {
		err = fmt.Errorf("create account for setup user: %w", err)
		m.rollbackSetup(ctx, userData.ID, "account provisioning failed", err, "")
		return nil, err
	}

	pat, err := m.accountManager.CreatePAT(ctx, accountID, userData.ID, userData.ID, setupPATTokenName, opts.PATExpireInDays)
	if err != nil {
		err = fmt.Errorf("create setup PAT: %w", err)
		m.rollbackSetup(ctx, userData.ID, "setup PAT provisioning failed", err, accountID)
		return nil, err
	}

	result.PATPlainToken = pat.PlainToken
	return result, nil
}

func (m *SetupService) rollbackSetup(ctx context.Context, userID, reason string, origErr error, accountID string) {
	if accountID != "" {
		if err := m.rollbackSetupAccount(ctx, accountID); err != nil {
			log.WithContext(ctx).Errorf("failed to roll back setup account %s for user %s after %s: original error: %v, rollback error: %v", accountID, userID, reason, origErr, err)
		} else {
			log.WithContext(ctx).Warnf("rolled back setup account %s for user %s after %s: %v", accountID, userID, reason, origErr)
		}
	}

	if err := m.instanceManager.RollbackSetup(ctx, userID); err != nil {
		log.WithContext(ctx).Errorf("failed to roll back setup user %s after %s: original error: %v, rollback error: %v", userID, reason, origErr, err)
		return
	}
	log.WithContext(ctx).Warnf("rolled back setup user %s after %s: %v", userID, reason, origErr)
}

// rollbackSetupAccount removes only the setup-created account data from the
// store. It intentionally avoids accountManager.DeleteAccount because the normal
// account deletion path also deletes users from the IdP; embedded IdP cleanup is
// owned by instanceManager.RollbackSetup.
func (m *SetupService) rollbackSetupAccount(ctx context.Context, accountID string) error {
	if m.accountManager == nil {
		return fmt.Errorf("account manager is required to roll back setup account")
	}

	accountStore := m.accountManager.GetStore()
	if accountStore == nil {
		return fmt.Errorf("account store is unavailable")
	}

	account, err := accountStore.GetAccount(ctx, accountID)
	if err != nil {
		if isNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("get setup account for rollback: %w", err)
	}

	if err := accountStore.DeleteAccount(ctx, account); err != nil {
		if isNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("delete setup account for rollback: %w", err)
	}

	return nil
}
