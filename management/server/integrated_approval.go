package server

import (
	"errors"

	"github.com/google/martian/v3/log"

	"github.com/netbirdio/netbird/management/server/account"
)

// UpdateIntegratedApprovalGroups updates the integrated approval groups for a specified account.
// It retrieves the account associated with the provided userID, then updates the integrated approval groups
// with the provided list of group ids. The updated account is then saved.
//
// Parameters:
//   - accountID: The ID of the account for which integrated approval groups are to be updated.
//   - userID: The ID of the user whose account is being updated.
//   - groups: A slice of strings representing the ids of integrated approval groups to be updated.
//
// Returns:
//   - error: An error if any occurred during the process, otherwise returns nil
func (am *DefaultAccountManager) UpdateIntegratedApprovalGroups(accountID string, userID string, groups []string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	ok, err := am.GroupValidation(accountID, groups)
	if err != nil {
		log.Debugf("error validating groups: %s", err.Error())
		return err
	}

	if !ok {
		log.Debugf("invalid groups")
		return errors.New("invalid groups")
	}

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
	extra.IntegratedApprovalGroups = groups

	am.cleanIntegratedApprovalFlag(a, groups)
	err = am.updateFlags(a, groups)
	if err != nil {
		saveErr := am.Store.SaveAccount(a)
		if saveErr != nil {
			log.Errorf("failed to save account: %s", saveErr)
		}
		return err
	}
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

// updateFlags set the requiresIntegratedApproval flag to true for all peers in the account what is part of the groups, but the peer not part of the already approved list in the edr db
func (am *DefaultAccountManager) updateFlags(a *Account, groups []string) error {
	approvedPeers, err := am.integratedPeerValidator.ApprovedPeersList(a.Id)
	if err != nil {
		log.Errorf("failed to get approved peers list: %s", err)
		return err
	}

	for peerID, peer := range a.Peers {
		peerGroups := a.GetPeerGroupsList(peerID)
		if !isPeerAssignedToIntegratedApprovalGroup(peerGroups, groups) {
			continue
		}

		// set true only that case if not yet approved in the edr db
		_, ok := approvedPeers[peerID]
		if ok {
			continue
		}
		peer.Status.RequiresIntegratedApproval = true
	}
	return nil
}

// cleanIntegratedApprovalFlag set the requireIntegratedApproval flag to false for all peers in the account what is not part of the groups
func (am *DefaultAccountManager) cleanIntegratedApprovalFlag(a *Account, groups []string) {
	for peerID, peer := range a.Peers {
		peerGroups := a.GetPeerGroupsList(peerID)
		if isPeerAssignedToIntegratedApprovalGroup(peerGroups, groups) {
			continue
		}
		peer.Status.RequiresIntegratedApproval = false
	}
}

func isPeerAssignedToIntegratedApprovalGroup(peersGroup []string, integratedApprovalGroups []string) bool {
	for _, peerGroup := range peersGroup {
		for _, ig := range integratedApprovalGroups {
			if ig == peerGroup {
				return true
			}
		}
	}
	return false
}
