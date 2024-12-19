package server

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// UpdateIntegratedValidatorGroups updates the integrated validator groups for a specified account.
// It retrieves the account associated with the provided userID, then updates the integrated validator groups
// with the provided list of group ids. The updated account is then saved.
//
// Parameters:
//   - accountID: The ID of the account for which integrated validator groups are to be updated.
//   - userID: The ID of the user whose account is being updated.
//   - groups: A slice of strings representing the ids of integrated validator groups to be updated.
//
// Returns:
//   - error: An error if any occurred during the process, otherwise returns nil
func (am *DefaultAccountManager) UpdateIntegratedValidatorGroups(ctx context.Context, accountID string, userID string, groups []string) error {
	ok, err := am.GroupValidation(ctx, accountID, groups)
	if err != nil {
		log.WithContext(ctx).Debugf("error validating groups: %s", err.Error())
		return err
	}

	if !ok {
		log.WithContext(ctx).Debugf("invalid groups")
		return errors.New("invalid groups")
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	a, err := am.Store.GetAccountByUser(ctx, userID)
	if err != nil {
		return err
	}

	var extra *account.ExtraSettings

	if a.Settings.Extra != nil {
		extra = a.Settings.Extra
	} else {
		extra = &account.ExtraSettings{}
		a.Settings.Extra = extra
	}
	extra.IntegratedValidatorGroups = groups
	return am.Store.SaveAccount(ctx, a)
}

func (am *DefaultAccountManager) GroupValidation(ctx context.Context, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return true, nil
	}

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		for _, groupID := range groupIDs {
			_, err := transaction.GetGroupByID(context.Background(), store.LockingStrengthShare, accountID, groupID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	return true, nil
}

func (am *DefaultAccountManager) GetValidatedPeers(account *types.Account) (map[string]struct{}, error) {
	return am.integratedPeerValidator.GetValidatedPeers(account.Id, account.Groups, account.Peers, account.Settings.Extra)
}
