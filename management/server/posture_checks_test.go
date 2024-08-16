package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/group"
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
		err := am.SavePostureChecks(context.Background(), account.Id, regularUserID, &posture.Checks{})
		assert.Error(t, err)

		// regular users cannot list check
		_, err = am.ListPostureChecks(context.Background(), account.Id, regularUserID)
		assert.Error(t, err)

		// should be possible to create posture check with uniq name
		err = am.SavePostureChecks(context.Background(), account.Id, adminUserID, &posture.Checks{
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
		checks, err := am.ListPostureChecks(context.Background(), account.Id, adminUserID)
		assert.NoError(t, err)
		assert.Len(t, checks, 1)

		// should not be possible to create posture check with non uniq name
		err = am.SavePostureChecks(context.Background(), account.Id, adminUserID, &posture.Checks{
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
		err = am.SavePostureChecks(context.Background(), account.Id, adminUserID, &posture.Checks{
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
		err = am.DeletePostureChecks(context.Background(), account.Id, postureCheckID, regularUserID)
		assert.Error(t, err)

		// admin should be able to delete posture checks
		err = am.DeletePostureChecks(context.Background(), account.Id, postureCheckID, adminUserID)
		assert.NoError(t, err)
		checks, err = am.ListPostureChecks(context.Background(), account.Id, adminUserID)
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

	account := newAccountWithId(context.Background(), accountID, groupAdminUserID, domain)
	account.Users[admin.Id] = admin
	account.Users[user.Id] = user

	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	return am.Store.GetAccount(context.Background(), account.Id)
}

func TestPostureCheckAccountPeerUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroup(context.Background(), account.Id, userID, &group.Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	assert.NoError(t, err)

	postureCheck := posture.Checks{
		ID:          "versionCheck",
		Name:        "Version Check",
		Description: "NetBird Version Check",
		AccountID:   account.Id,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.28.0",
			},
		},
	}

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Saving unused posture check should not update account peers and not send peer update
	t.Run("saving unused posture check", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	policy := Policy{
		ID:      "policy",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"group-id"},
				Destinations:  []string{"group-id"},
				Bidirectional: true,
				Action:        PolicyTrafficActionAccept,
			},
		},
		SourcePostureChecks: []string{postureCheck.ID},
	}

	// Adding posture check to policy should trigger update account peers and send peer update
	t.Run("adding posture check to policy", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}

	})

	// Updating used posture checks should update account peers and send peer update
	t.Run("updating used posture check", func(t *testing.T) {
		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.28.6",
			},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Saving unchanged posture check should trigger account peers update and not send peer update
	// since there is no change in the network map
	t.Run("saving unchanged posture check", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Removing posture check from policy should trigger account peers update and send peer update
	t.Run("removing posture check from policy", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		policy.SourcePostureChecks = []string{}

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
