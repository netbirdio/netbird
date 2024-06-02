package server

import (
	"errors"

	"github.com/google/martian/v3/log"

	"github.com/netbirdio/netbird/management/server/account"
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
func (am *DefaultAccountManager) UpdateIntegratedValidatorGroups(accountID string, userID string, groups []string) error {
	ok, err := am.GroupValidation(accountID, groups)
	if err != nil {
		log.Debugf("error validating groups: %s", err.Error())
		return err
	}

	if !ok {
		log.Debugf("invalid groups")
		return errors.New("invalid groups")
	}

	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	a, err := am.Store.GetAccountByUser(userID)
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
	return am.Store.SaveAccount(a)
}

func (am *DefaultAccountManager) GroupValidation(accountId string, groups []string) (bool, error) {
	if len(groups) == 0 {
		return true, nil
	}
	accountsGroups, err := am.ListGroups(accountId)
	if err != nil {
		return false, err
	}
	for _, group := range groups {
		var found bool
		for _, accountGroup := range accountsGroups {
			if accountGroup.ID == group {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}

func (am *DefaultAccountManager) GetValidatedPeers(account *Account) (map[string]struct{}, error) {
	return am.integratedPeerValidator.GetValidatedPeers(account.Id, account.Groups, account.Peers, account.Settings.Extra)
}
