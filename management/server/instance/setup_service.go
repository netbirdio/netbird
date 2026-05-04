package instance

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	setupPATTokenName = "setup-token"

	// SetupPATEnabledEnvKey enables setup-time Personal Access Token creation.
	SetupPATEnabledEnvKey = "NB_SETUP_PAT_ENABLED"

	setupPATDefaultExpireDays = 1
)

// SetupOptions controls optional work performed during initial instance setup.
type SetupOptions struct {
	// CreatePAT requests creation of a setup Personal Access Token. It is honored
	// only when SetupPATEnabledEnvKey is set to "true".
	CreatePAT bool
	// PATExpireInDays defaults to 1 day when CreatePAT is requested and setup PAT
	// creation is enabled.
	PATExpireInDays *int
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
	setupPATEnabled bool
}

// NewSetupService creates a setup use-case service.
func NewSetupService(instanceManager Manager, accountManager account.Manager) *SetupService {
	return &SetupService{
		instanceManager: instanceManager,
		accountManager:  accountManager,
		setupPATEnabled: os.Getenv(SetupPATEnabledEnvKey) == "true",
	}
}

func normalizeSetupOptions(opts SetupOptions, setupPATEnabled bool) (SetupOptions, error) {
	if !opts.CreatePAT {
		return opts, nil
	}

	if !setupPATEnabled {
		opts.CreatePAT = false
		opts.PATExpireInDays = nil
		return opts, nil
	}

	if opts.PATExpireInDays == nil {
		defaultExpireInDays := setupPATDefaultExpireDays
		opts.PATExpireInDays = &defaultExpireInDays
	}

	if *opts.PATExpireInDays < account.PATMinExpireDays || *opts.PATExpireInDays > account.PATMaxExpireDays {
		return opts, status.Errorf(status.InvalidArgument, "pat_expire_in must be between %d and %d", account.PATMinExpireDays, account.PATMaxExpireDays)
	}

	return opts, nil
}

// SetupOwner creates the initial owner user and, when requested and enabled by
// SetupPATEnabledEnvKey, provisions the account and a setup Personal Access
// Token. If account or PAT provisioning fails, created resources are rolled
// back so setup can be retried. If account rollback fails, user rollback is
// skipped to avoid leaving an account without its owner user.
func (m *SetupService) SetupOwner(ctx context.Context, email, password, name string, opts SetupOptions) (*SetupResult, error) {
	opts, err := normalizeSetupOptions(opts, m.setupPATEnabled)
	if err != nil {
		return nil, err
	}

	if opts.CreatePAT && m.accountManager == nil {
		return nil, fmt.Errorf("account manager is required to create setup PAT")
	}

	userData, err := m.instanceManager.CreateOwnerUser(ctx, email, password, name)
	if err != nil {
		return nil, err
	}

	result := &SetupResult{User: userData}
	if !opts.CreatePAT {
		return result, nil
	}

	userAuth := auth.UserAuth{
		UserId: userData.ID,
		Email:  userData.Email,
		Name:   userData.Name,
	}

	accountID, err := m.accountManager.GetAccountIDByUserID(ctx, userAuth)
	if err != nil {
		err = fmt.Errorf("create account for setup user: %w", err)
		if rollbackErr := m.rollbackSetup(ctx, userData.ID, "account provisioning failed", err, ""); rollbackErr != nil {
			return nil, fmt.Errorf("%w; failed to roll back setup resources: %v", err, rollbackErr)
		}
		return nil, err
	}

	pat, err := m.accountManager.CreatePAT(ctx, accountID, userData.ID, userData.ID, setupPATTokenName, *opts.PATExpireInDays)
	if err != nil {
		err = fmt.Errorf("create setup PAT: %w", err)
		if rollbackErr := m.rollbackSetup(ctx, userData.ID, "setup PAT provisioning failed", err, accountID); rollbackErr != nil {
			return nil, fmt.Errorf("%w; failed to roll back setup resources: %v", err, rollbackErr)
		}
		return nil, err
	}

	result.PATPlainToken = pat.PlainToken
	return result, nil
}

func (m *SetupService) rollbackSetup(ctx context.Context, userID, reason string, origErr error, accountID string) error {
	if accountID == "" {
		resolvedAccountID, err := m.lookupSetupAccountIDForRollback(ctx, userID)
		if err != nil {
			rollbackErr := fmt.Errorf("resolve setup account for rollback: %w", err)
			log.WithContext(ctx).Errorf("failed to resolve setup account for user %s after %s: original error: %v, rollback error: %v", userID, reason, origErr, rollbackErr)
			return rollbackErr
		}
		accountID = resolvedAccountID
	}

	if accountID != "" {
		if err := m.rollbackSetupAccount(ctx, accountID); err != nil {
			rollbackErr := fmt.Errorf("roll back setup account %s: %w", accountID, err)
			log.WithContext(ctx).Errorf("failed to roll back setup account %s for user %s after %s: original error: %v, rollback error: %v", accountID, userID, reason, origErr, rollbackErr)
			return rollbackErr
		}
		log.WithContext(ctx).Warnf("rolled back setup account %s for user %s after %s: %v", accountID, userID, reason, origErr)
	}

	if err := m.instanceManager.RollbackSetup(ctx, userID); err != nil {
		rollbackErr := fmt.Errorf("roll back setup user %s: %w", userID, err)
		log.WithContext(ctx).Errorf("failed to roll back setup user %s after %s: original error: %v, rollback error: %v", userID, reason, origErr, rollbackErr)
		return rollbackErr
	}
	log.WithContext(ctx).Warnf("rolled back setup user %s after %s: %v", userID, reason, origErr)
	return nil
}

func (m *SetupService) lookupSetupAccountIDForRollback(ctx context.Context, userID string) (string, error) {
	if m.accountManager == nil {
		return "", fmt.Errorf("account manager is required to resolve setup account")
	}

	accountStore := m.accountManager.GetStore()
	if accountStore == nil {
		return "", fmt.Errorf("account store is unavailable")
	}

	accountID, err := accountStore.GetAccountIDByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		if isNotFoundError(err) {
			return "", nil
		}
		return "", fmt.Errorf("get setup account ID for rollback: %w", err)
	}

	return accountID, nil
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
