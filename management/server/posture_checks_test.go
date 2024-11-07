package server

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/group"

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

	accountID, err := initTestPostureChecksAccount(am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	t.Run("Generic posture check flow", func(t *testing.T) {
		// regular users can not create checks
		err := am.SavePostureChecks(context.Background(), accountID, regularUserID, &posture.Checks{}, false)
		assert.Error(t, err)

		// regular users cannot list check
		_, err = am.ListPostureChecks(context.Background(), accountID, regularUserID)
		assert.Error(t, err)

		// should be possible to create posture check with uniq name
		err = am.SavePostureChecks(context.Background(), accountID, adminUserID, &posture.Checks{
			ID:        postureCheckID,
			AccountID: accountID,
			Name:      postureCheckName,
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.26.0",
				},
			},
		}, false)
		assert.NoError(t, err)

		// admin users can list check
		checks, err := am.ListPostureChecks(context.Background(), accountID, adminUserID)
		assert.NoError(t, err)
		assert.Len(t, checks, 1)

		// should not be possible to create posture check with non uniq name
		err = am.SavePostureChecks(context.Background(), accountID, adminUserID, &posture.Checks{
			ID:        "new-id",
			AccountID: accountID,
			Name:      postureCheckName,
			Checks: posture.ChecksDefinition{
				GeoLocationCheck: &posture.GeoLocationCheck{
					Locations: []posture.Location{
						{
							CountryCode: "DE",
						},
					},
				},
			},
		}, false)
		assert.Error(t, err)

		// admins can update posture checks
		err = am.SavePostureChecks(context.Background(), accountID, adminUserID, &posture.Checks{
			ID:        postureCheckID,
			AccountID: accountID,
			Name:      postureCheckName,
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.27.0",
				},
			},
		}, false)
		assert.NoError(t, err)

		// users should not be able to delete posture checks
		err = am.DeletePostureChecks(context.Background(), accountID, postureCheckID, regularUserID)
		assert.Error(t, err)

		// admin should be able to delete posture checks
		err = am.DeletePostureChecks(context.Background(), accountID, postureCheckID, adminUserID)
		assert.NoError(t, err)
		checks, err = am.ListPostureChecks(context.Background(), accountID, adminUserID)
		assert.NoError(t, err)
		assert.Len(t, checks, 0)
	})
}

func initTestPostureChecksAccount(am *DefaultAccountManager) (string, error) {
	accountID := "testingAccount"
	domain := "example.com"

	err := newAccountWithId(context.Background(), am.Store, accountID, groupAdminUserID, domain)
	if err != nil {
		return "", err
	}

	err = am.Store.SaveUsers(context.Background(), LockingStrengthUpdate, []*User{
		{
			Id:        adminUserID,
			AccountID: accountID,
			Role:      UserRoleAdmin,
		},
		{
			Id:        regularUserID,
			AccountID: accountID,
			Role:      UserRoleUser,
		},
	})
	if err != nil {
		return "", err
	}

	return accountID, nil
}

func TestPostureCheckAccountPeersUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroups(context.Background(), account.Id, userID, []*group.Group{
		{
			ID:        "groupA",
			AccountID: account.Id,
			Name:      "GroupA",
			Peers:     []string{peer1.ID, peer2.ID, peer3.ID},
		},
		{
			ID:        "groupB",
			AccountID: account.Id,
			Name:      "GroupB",
			Peers:     []string{},
		},
		{
			ID:        "groupC",
			AccountID: account.Id,
			Name:      "GroupC",
			Peers:     []string{},
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

		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, false)
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
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	policy := Policy{
		ID:        "policyA",
		AccountID: account.Id,
		Enabled:   true,
		Rules: []*PolicyRule{
			{
				ID:            "ruleA",
				PolicyID:      "policyA",
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

		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
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

	err = manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, false)
	assert.NoError(t, err)

	// Updating linked posture check to policy with no peers should not trigger account peers update and not send peer update
	t.Run("updating linked posture check to policy with no peers", func(t *testing.T) {
		policy = Policy{
			ID:        "policyB",
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*PolicyRule{
				{
					ID:            "ruleB",
					PolicyID:      "policyB",
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
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, true)
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
			ID:        "policyB",
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*PolicyRule{
				{
					ID:            "ruleB",
					PolicyID:      "policyB",
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
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Updating linked client posture check to policy where source has peers but destination does not,
	// should trigger account peers update and send peer update
	t.Run("updating linked posture check to policy where source has peers but destination does not", func(t *testing.T) {
		policy = Policy{
			ID:        "policyB",
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*PolicyRule{
				{
					ID:            "ruleB",
					PolicyID:      "policyB",
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
			ProcessCheck: &posture.ProcessCheck{
				Processes: []posture.Process{
					{
						LinuxPath: "/usr/bin/netbird",
					},
				},
			},
		}
		err := manager.SavePostureChecks(context.Background(), account.Id, userID, &postureCheck, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}

func TestArePostureCheckChangesAffectingPeers(t *testing.T) {
	manager, err := createManager(t)
	require.NoError(t, err, "failed to create account manager")

	accountID, err := initTestPostureChecksAccount(manager)
	require.NoError(t, err, "failed to init testing account")

	groupA := &group.Group{
		ID:        "groupA",
		AccountID: accountID,
		Peers:     []string{"peer1"},
	}

	groupB := &group.Group{
		ID:        "groupB",
		AccountID: accountID,
		Peers:     []string{},
	}
	err = manager.Store.SaveGroups(context.Background(), LockingStrengthUpdate, []*group.Group{groupA, groupB})
	require.NoError(t, err, "failed to save groups")

	policy := &Policy{
		ID:        "policyA",
		AccountID: accountID,
		Rules: []*PolicyRule{
			{
				ID:           "ruleA",
				PolicyID:     "policyA",
				Enabled:      true,
				Sources:      []string{"groupA"},
				Destinations: []string{"groupA"},
			},
		},
		SourcePostureChecks: []string{"checkA"},
	}
	err = manager.Store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
	require.NoError(t, err, "failed to save policy")

	postureCheckA := &posture.Checks{
		ID:        "checkA",
		Name:      "checkA",
		AccountID: accountID,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.33.1"},
		},
	}
	err = manager.SavePostureChecks(context.Background(), accountID, adminUserID, postureCheckA, false)
	require.NoError(t, err, "failed to save postureCheckA")

	postureCheckB := &posture.Checks{
		ID:        "checkB",
		Name:      "checkB",
		AccountID: accountID,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.33.1"},
		},
	}
	err = manager.SavePostureChecks(context.Background(), accountID, adminUserID, postureCheckB, false)
	require.NoError(t, err, "failed to save postureCheckB")

	t.Run("posture check exists and is linked to policy with peers", func(t *testing.T) {
		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkA", true)
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("posture check exists but is not linked to any policy", func(t *testing.T) {
		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkB", true)
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("posture check does not exist", func(t *testing.T) {
		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "unknown", false)
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("posture check is linked to policy with no peers in source groups", func(t *testing.T) {
		policy.Rules[0].Sources = []string{"groupB"}
		policy.Rules[0].Destinations = []string{"groupA"}
		err = manager.Store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
		require.NoError(t, err, "failed to update policy")

		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkA", true)
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("posture check is linked to policy with no peers in destination groups", func(t *testing.T) {
		policy.Rules[0].Sources = []string{"groupA"}
		policy.Rules[0].Destinations = []string{"groupB"}
		err = manager.Store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
		require.NoError(t, err, "failed to update policy")

		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkA", true)
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("posture check is linked to policy but no peers in groups", func(t *testing.T) {
		groupA.Peers = []string{}
		err = manager.Store.SaveGroup(context.Background(), LockingStrengthUpdate, groupA)
		require.NoError(t, err, "failed to save groups")

		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkA", true)
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("posture check is linked to policy with non-existent group", func(t *testing.T) {
		policy.Rules[0].Sources = []string{"nonExistentGroup"}
		policy.Rules[0].Destinations = []string{"nonExistentGroup"}
		err = manager.Store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
		require.NoError(t, err, "failed to update policy")

		result, err := manager.arePostureCheckChangesAffectPeers(context.Background(), accountID, "checkA", true)
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, sErr.Type())
		assert.False(t, result)
	})
}
