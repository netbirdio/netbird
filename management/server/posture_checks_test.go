package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/group"
	"github.com/rs/xid"
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

func TestPostureCheckAccountPeersUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroups(context.Background(), account.Id, userID, []*group.Group{
		{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{peer1.ID, peer2.ID, peer3.ID},
		},
		{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{},
		},
		{
			ID:    "groupC",
			Name:  "GroupC",
			Peers: []string{},
		},
	})
	assert.NoError(t, err)

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	postureCheck := posture.Checks{
		ID:        "postureCheck",
		Name:      "postureCheck",
		AccountID: account.Id,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.28.0",
			},
		},
	}

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

	// Updating unused posture check should not update account peers and not send peer update
	t.Run("updating unused posture check", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.29.0",
			},
		}
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	policy := Policy{
		ID:      "policyA",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:            xid.New().String(),
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        PolicyTrafficActionAccept,
			},
		},
		SourcePostureChecks: []string{postureCheck.ID},
	}

	// Linking posture check to policy should trigger update account peers and send peer update
	t.Run("linking posture check to policy with peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Updating linked posture checks should update account peers and send peer update
	t.Run("updating linked to posture check with peers", func(t *testing.T) {
		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.29.0",
			},
			ProcessCheck: &posture.ProcessCheck{
				Processes: []posture.Process{
					{LinuxPath: "/usr/bin/netbird", MacPath: "/usr/local/bin/netbird"},
				},
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

	// Saving unchanged posture check should not trigger account peers update and not send peer update
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

		err := manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting unused posture check should not trigger account peers update and not send peer update
	t.Run("deleting unused posture check", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeletePostureChecks(context.Background(), account.Id, "postureCheck", userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	err = manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
	assert.NoError(t, err)

	// Updating linked posture check to policy with no peers should not trigger account peers update and not send peer update
	t.Run("updating linked posture check to policy with no peers", func(t *testing.T) {
		policy = Policy{
			ID:      "policyB",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupB"},
					Destinations:  []string{"groupC"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
			SourcePostureChecks: []string{postureCheck.ID},
		}
		err = manager.SavePolicy(context.Background(), account.Id, userID, &policy, false)
		assert.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.29.0",
			},
		}
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Updating linked posture check to policy where destination has peers but source does not
	// should trigger account peers update and send peer update
	t.Run("updating linked posture check to policy where destination has peers but source does not", func(t *testing.T) {
		updMsg1 := manager.peersUpdateManager.CreateChannel(context.Background(), peer2.ID)
		t.Cleanup(func() {
			manager.peersUpdateManager.CloseChannel(context.Background(), peer2.ID)
		})
		policy = Policy{
			ID:      "policyB",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:            xid.New().String(),
					Enabled:       true,
					Sources:       []string{"groupB"},
					Destinations:  []string{"groupA"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
			SourcePostureChecks: []string{postureCheck.ID},
		}

		err = manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
		assert.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			close(done)
		}()

		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.29.0",
			},
		}
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Updating linked posture check to policy where source has peers but destination does not,
	// should trigger account peers update and send peer update
	t.Run("updating linked posture check to policy where source has peers but destination does not", func(t *testing.T) {
		policy = Policy{
			ID:      "policyB",
			Enabled: true,
			Rules: []*PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupB"},
					Bidirectional: true,
					Action:        PolicyTrafficActionAccept,
				},
			},
			SourcePostureChecks: []string{postureCheck.ID},
		}
		err = manager.SavePolicy(context.Background(), account.Id, userID, &policy, true)
		assert.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		postureCheck.Checks = posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.29.0",
			},
		}
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
