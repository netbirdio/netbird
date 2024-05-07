package server

import (
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

func (am *DefaultAccountManager) GetPostureChecks(accountID, postureChecksID, userID string) (*posture.Checks, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view posture checks")
	}

	for _, postureChecks := range account.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "posture checks with ID %s not found", postureChecksID)
}

func (am *DefaultAccountManager) SavePostureChecks(accountID, userID string, postureChecks *posture.Checks) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view posture checks")
	}

	if err := postureChecks.Validate(); err != nil {
		return status.Errorf(status.BadRequest, err.Error())
	}

	exists, uniqName := am.savePostureChecks(account, postureChecks)

	// we do not allow create new posture checks with non uniq name
	if !exists && !uniqName {
		return status.Errorf(status.PreconditionFailed, "Posture check name should be unique")
	}

	action := activity.PostureCheckCreated
	if exists {
		action = activity.PostureCheckUpdated
		account.Network.IncSerial()
	}

	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.StoreEvent(userID, postureChecks.ID, accountID, action, postureChecks.EventMeta())
	if exists {
		am.updateAccountPeers(account)
	}

	return nil
}

func (am *DefaultAccountManager) DeletePostureChecks(accountID, postureChecksID, userID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view posture checks")
	}

	postureChecks, err := am.deletePostureChecks(account, postureChecksID)
	if err != nil {
		return err
	}

	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.StoreEvent(userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	return nil
}

func (am *DefaultAccountManager) ListPostureChecks(accountID, userID string) ([]*posture.Checks, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view posture checks")
	}

	return account.PostureChecks, nil
}

func (am *DefaultAccountManager) savePostureChecks(account *Account, postureChecks *posture.Checks) (exists, uniqName bool) {
	uniqName = true
	for i, p := range account.PostureChecks {
		if !exists && p.ID == postureChecks.ID {
			account.PostureChecks[i] = postureChecks
			exists = true
		}
		if p.Name == postureChecks.Name {
			uniqName = false
		}
	}
	if !exists {
		account.PostureChecks = append(account.PostureChecks, postureChecks)
	}
	return
}

func (am *DefaultAccountManager) deletePostureChecks(account *Account, postureChecksID string) (*posture.Checks, error) {
	postureChecksIdx := -1
	for i, postureChecks := range account.PostureChecks {
		if postureChecks.ID == postureChecksID {
			postureChecksIdx = i
			break
		}
	}
	if postureChecksIdx < 0 {
		return nil, status.Errorf(status.NotFound, "posture checks with ID %s doesn't exist", postureChecksID)
	}

	// check policy links
	for _, policy := range account.Policies {
		for _, id := range policy.SourcePostureChecks {
			if id == postureChecksID {
				return nil, status.Errorf(status.PreconditionFailed, "posture checks have been linked to policy: %s", policy.Name)
			}
		}
	}

	postureChecks := account.PostureChecks[postureChecksIdx]
	account.PostureChecks = append(account.PostureChecks[:postureChecksIdx], account.PostureChecks[postureChecksIdx+1:]...)

	return postureChecks, nil
}
