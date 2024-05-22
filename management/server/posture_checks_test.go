package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/posture"
)

const (
	adminUserID      = "adminUserID"
	regularUserID    = "regularUserID"
	postureCheckID   = "existing-id"
	postureCheckName = "Existing check"
)

func TestDefaultAccountManager_PostureCheck(t *testing.T) {
	am, err := createManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestPostureChecksAccount(am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	t.Run("Generic posture check flow", func(t *testing.T) {
		// regular users can not create checks
		err := am.SavePostureChecks(account.Id, regularUserID, &posture.Checks{})
		assert.Error(t, err)

		// regular users cannot list check
		_, err = am.ListPostureChecks(account.Id, regularUserID)
		assert.Error(t, err)

		// should be possible to create posture check with uniq name
		err = am.SavePostureChecks(account.Id, adminUserID, &posture.Checks{
			ID:   postureCheckID,
			Name: postureCheckName,
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.26.0",
				},
			},
		})
		assert.NoError(t, err)

		// admin users can list check
		checks, err := am.ListPostureChecks(account.Id, adminUserID)
		assert.NoError(t, err)
		assert.Len(t, checks, 1)

		// should not be possible to create posture check with non uniq name
		err = am.SavePostureChecks(account.Id, adminUserID, &posture.Checks{
			ID:   "new-id",
			Name: postureCheckName,
			Checks: posture.ChecksDefinition{
				GeoLocationCheck: &posture.GeoLocationCheck{
					Locations: []posture.Location{
						{
							CountryCode: "DE",
						},
					},
				},
			},
		})
		assert.Error(t, err)

		// admins can update posture checks
		err = am.SavePostureChecks(account.Id, adminUserID, &posture.Checks{
			ID:   postureCheckID,
			Name: postureCheckName,
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.27.0",
				},
			},
		})
		assert.NoError(t, err)

		// users should not be able to delete posture checks
		err = am.DeletePostureChecks(account.Id, postureCheckID, regularUserID)
		assert.Error(t, err)

		// admin should be able to delete posture checks
		err = am.DeletePostureChecks(account.Id, postureCheckID, adminUserID)
		assert.NoError(t, err)
		checks, err = am.ListPostureChecks(account.Id, adminUserID)
		assert.NoError(t, err)
		assert.Len(t, checks, 0)
	})
}

func initTestPostureChecksAccount(am *DefaultAccountManager) (*Account, error) {
	accountID := "testingAccount"
	domain := "example.com"

	admin := &User{
		Id:   adminUserID,
		Role: UserRoleAdmin,
	}
	user := &User{
		Id:   regularUserID,
		Role: UserRoleUser,
	}

	account := newAccountWithId(accountID, groupAdminUserID, domain)
	account.Users[admin.Id] = admin
	account.Users[user.Id] = user

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return am.Store.GetAccount(account.Id)
}
