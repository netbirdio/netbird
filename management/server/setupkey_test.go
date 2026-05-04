package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestDefaultAccountManager_SaveSetupKey(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateGroups(context.Background(), account.Id, userID, []*types.Group{
		{
			ID:    "group_1",
			Name:  "group_name_1",
			Peers: []string{},
		},
		{
			ID:    "group_2",
			Name:  "group_name_2",
			Peers: []string{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	expiresIn := time.Hour
	keyName := "my-test-key"

	key, err := manager.CreateSetupKey(context.Background(), account.Id, keyName, types.SetupKeyReusable, expiresIn, []string{},
		types.SetupKeyUnlimitedUsage, userID, false, false)
	if err != nil {
		t.Fatal(err)
	}

	autoGroups := []string{"group_1", "group_2"}
	revoked := true
	newKey, err := manager.SaveSetupKey(context.Background(), account.Id, &types.SetupKey{
		Id:         key.Id,
		Revoked:    revoked,
		AutoGroups: autoGroups,
	}, userID)
	if err != nil {
		t.Fatal(err)
	}

	assertKey(t, newKey, keyName, revoked, "reusable", 0, key.CreatedAt, key.GetExpiresAt(),
		key.Id, time.Now().UTC(), autoGroups, true)

	// check the corresponding events that should have been generated
	ev := getEvent(t, account.Id, manager, activity.SetupKeyRevoked)

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, keyName, ev.Meta["name"])
	assert.Equal(t, fmt.Sprint(key.Type), fmt.Sprint(ev.Meta["type"]))
	assert.NotEmpty(t, ev.Meta["key"])
	assert.Equal(t, userID, ev.InitiatorID)
	assert.Equal(t, key.Id, ev.TargetID)

	groupAll, err := account.GetGroupAll()
	assert.NoError(t, err)

	// saving setup key with All group assigned to auto groups should return error
	autoGroups = append(autoGroups, groupAll.ID)
	_, err = manager.SaveSetupKey(context.Background(), account.Id, &types.SetupKey{
		Id:         key.Id,
		Revoked:    revoked,
		AutoGroups: autoGroups,
	}, userID)
	assert.Error(t, err, "should not save setup key with All group assigned in auto groups")
}

func TestDefaultAccountManager_CreateSetupKey(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "group_1",
		Name:  "group_name_1",
		Peers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "group_2",
		Name:  "group_name_2",
		Peers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	groupAll, err := account.GetGroupAll()
	assert.NoError(t, err)

	type testCase struct {
		name string

		expectedKeyName   string
		expectedUsedTimes int
		expectedType      string
		expectedGroups    []string
		expectedCreatedAt time.Time
		expectedUpdatedAt time.Time
		expectedExpiresAt time.Time
		expectedFailure   bool // indicates whether key creation should fail
	}

	now := time.Now().UTC()
	expiresIn := time.Hour
	testCase1 := testCase{
		name:              "Should Create Setup Key successfully",
		expectedKeyName:   "my-test-key",
		expectedUsedTimes: 0,
		expectedType:      "reusable",
		expectedGroups:    []string{"group_1", "group_2"},
		expectedCreatedAt: now,
		expectedUpdatedAt: now,
		expectedExpiresAt: now.Add(expiresIn),
		expectedFailure:   false,
	}
	testCase2 := testCase{
		name:            "Create Setup Key should fail because of unexistent group",
		expectedKeyName: "my-test-key",
		expectedGroups:  []string{"FAKE"},
		expectedFailure: true,
	}
	testCase3 := testCase{
		name:            "Create Setup Key should fail because of All group",
		expectedKeyName: "my-test-key",
		expectedGroups:  []string{groupAll.ID},
		expectedFailure: true,
	}

	for _, tCase := range []testCase{testCase1, testCase2, testCase3} {
		t.Run(tCase.name, func(t *testing.T) {
			key, err := manager.CreateSetupKey(context.Background(), account.Id, tCase.expectedKeyName, types.SetupKeyReusable, expiresIn,
				tCase.expectedGroups, types.SetupKeyUnlimitedUsage, userID, false, false)

			if tCase.expectedFailure {
				if err == nil {
					t.Fatal("expected to fail")
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			assertKey(t, key, tCase.expectedKeyName, false, tCase.expectedType, tCase.expectedUsedTimes,
				tCase.expectedCreatedAt, tCase.expectedExpiresAt, key.Id,
				tCase.expectedUpdatedAt, tCase.expectedGroups, false)

			// check the corresponding events that should have been generated
			ev := getEvent(t, account.Id, manager, activity.SetupKeyCreated)

			assert.NotNil(t, ev)
			assert.Equal(t, account.Id, ev.AccountID)
			assert.Equal(t, tCase.expectedKeyName, ev.Meta["name"])
			assert.Equal(t, tCase.expectedType, fmt.Sprint(ev.Meta["type"]))
			assert.NotEmpty(t, ev.Meta["key"])
		})
	}

}

func TestGetSetupKeys(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	if err != nil {
		t.Fatal(err)
	}

	plainKey, err := manager.CreateSetupKey(context.Background(), account.Id, "key1", types.SetupKeyReusable, time.Hour, nil, types.SetupKeyUnlimitedUsage, userID, false, false)
	if err != nil {
		t.Fatal(err)
	}

	type testCase struct {
		name            string
		keyId           string
		expectedFailure bool
	}

	testCase1 := testCase{
		name:            "Should get existing Setup Key",
		keyId:           plainKey.Id,
		expectedFailure: false,
	}
	testCase2 := testCase{
		name:            "Should fail to get non-existent Setup Key",
		keyId:           "some key",
		expectedFailure: true,
	}

	for _, tCase := range []testCase{testCase1, testCase2} {
		t.Run(tCase.name, func(t *testing.T) {
			key, err := manager.GetSetupKey(context.Background(), account.Id, userID, tCase.keyId)

			if tCase.expectedFailure {
				if err == nil {
					t.Fatal("expected to fail")
				}
				return
			}

			assert.NotEqual(t, plainKey.Key, key.Key)
		})
	}
}

func TestGenerateDefaultSetupKey(t *testing.T) {
	expectedName := "Default key"
	expectedRevoke := false
	expectedType := "reusable"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now().UTC()
	expectedUpdatedAt := time.Now().UTC()
	expectedExpiresAt := time.Now().UTC().Add(24 * 30 * time.Hour)
	var expectedAutoGroups []string

	key, _ := types.GenerateDefaultSetupKey()

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt,
		expectedExpiresAt, key.Id, expectedUpdatedAt, expectedAutoGroups, true)

}

func TestGenerateSetupKey(t *testing.T) {
	expectedName := "key"
	expectedRevoke := false
	expectedType := "one-off"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now().UTC()
	expectedExpiresAt := time.Now().UTC().Add(time.Hour)
	expectedUpdatedAt := time.Now().UTC()
	var expectedAutoGroups []string

	key, _ := types.GenerateSetupKey(expectedName, types.SetupKeyOneOff, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt,
		expectedExpiresAt, key.Id, expectedUpdatedAt, expectedAutoGroups, true)

}

func TestSetupKey_IsValid(t *testing.T) {
	validKey, _ := types.GenerateSetupKey("valid key", types.SetupKeyOneOff, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	if !validKey.IsValid() {
		t.Errorf("expected key to be valid, got invalid %v", validKey)
	}

	// expired
	expiredKey, _ := types.GenerateSetupKey("invalid key", types.SetupKeyOneOff, -time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	if expiredKey.IsValid() {
		t.Errorf("expected key to be invalid due to expiration, got valid %v", expiredKey)
	}

	// revoked
	revokedKey, _ := types.GenerateSetupKey("invalid key", types.SetupKeyOneOff, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	revokedKey.Revoked = true
	if revokedKey.IsValid() {
		t.Errorf("expected revoked key to be invalid, got valid %v", revokedKey)
	}

	// overused
	overUsedKey, _ := types.GenerateSetupKey("invalid key", types.SetupKeyOneOff, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	overUsedKey.UsedTimes = 1
	if overUsedKey.IsValid() {
		t.Errorf("expected overused key to be invalid, got valid %v", overUsedKey)
	}

	// overused
	reusableKey, _ := types.GenerateSetupKey("valid key", types.SetupKeyReusable, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	reusableKey.UsedTimes = 99
	if !reusableKey.IsValid() {
		t.Errorf("expected reusable key to be valid when used many times, got valid %v", reusableKey)
	}
}

func assertKey(t *testing.T, key *types.SetupKey, expectedName string, expectedRevoke bool, expectedType string,
	expectedUsedTimes int, expectedCreatedAt time.Time, expectedExpiresAt time.Time, expectedID string,
	expectedUpdatedAt time.Time, expectedAutoGroups []string, expectHashedKey bool) {
	t.Helper()
	if key.Name != expectedName {
		t.Errorf("expected setup key to have Name %v, got %v", expectedName, key.Name)
	}

	if key.Revoked != expectedRevoke {
		t.Errorf("expected setup key to have Revoke %v, got %v", expectedRevoke, key.Revoked)
	}

	if string(key.Type) != expectedType {
		t.Errorf("expected setup key to have Type %v, got %v", expectedType, key.Type)
	}

	if key.UsedTimes != expectedUsedTimes {
		t.Errorf("expected setup key to have UsedTimes = %v, got %v", expectedUsedTimes, key.UsedTimes)
	}

	if key.GetExpiresAt().Sub(expectedExpiresAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have ExpiresAt ~ %v, got %v", expectedExpiresAt, key.GetExpiresAt())
	}

	if key.UpdatedAt.Sub(expectedUpdatedAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have UpdatedAt ~ %v, got %v", expectedUpdatedAt, key.UpdatedAt)
	}

	if key.CreatedAt.Sub(expectedCreatedAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have CreatedAt ~ %v, got %v", expectedCreatedAt, key.CreatedAt)
	}

	if expectHashedKey {
		if !isValidBase64SHA256(key.Key) {
			t.Errorf("expected key to be hashed, got %v", key.Key)
		}
	} else {
		_, err := uuid.Parse(key.Key)
		if err != nil {
			t.Errorf("expected key to be a valid UUID, got %v, %v", key.Key, err)
		}
	}

	if !strings.HasSuffix(key.KeySecret, "****") {
		t.Errorf("expected key secret to be secure, got %v", key.Key)
	}

	if key.Id != expectedID {
		t.Errorf("expected key Id %v, got %v", expectedID, key.Id)
	}

	if len(key.AutoGroups) != len(expectedAutoGroups) {
		t.Errorf("expected key AutoGroups size=%d, got %d", len(expectedAutoGroups), len(key.AutoGroups))
	}
	assert.ElementsMatch(t, key.AutoGroups, expectedAutoGroups, "expected key AutoGroups to be equal")
}

func isValidBase64SHA256(encodedKey string) bool {
	decoded, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return false
	}

	if len(decoded) != sha256.Size {
		return false
	}

	return true
}

func TestSetupKey_Copy(t *testing.T) {

	key, _ := types.GenerateSetupKey("key name", types.SetupKeyOneOff, time.Hour, []string{}, types.SetupKeyUnlimitedUsage, false, false)
	keyCopy := key.Copy()

	assertKey(t, keyCopy, key.Name, key.Revoked, string(key.Type), key.UsedTimes, key.CreatedAt, key.GetExpiresAt(), key.Id,
		key.UpdatedAt, key.AutoGroups, true)

}

func TestSetupKeyAccountPeersUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	assert.NoError(t, err)

	policy := &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"group"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}
	_, err = manager.SavePolicy(context.Background(), account.Id, userID, policy, true)
	require.NoError(t, err)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	var setupKey *types.SetupKey

	// Creating setup key should not update account peers and not send peer update
	t.Run("creating setup key", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		setupKey, err = manager.CreateSetupKey(context.Background(), account.Id, "key1", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Saving setup key should not update account peers and not send peer update
	t.Run("saving setup key", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveSetupKey(context.Background(), account.Id, setupKey, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})
}

func TestDefaultAccountManager_CreateSetupKey_ShouldNotAllowToUpdateRevokedKey(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	if err != nil {
		t.Fatal(err)
	}

	key, err := manager.CreateSetupKey(context.Background(), account.Id, "testName", types.SetupKeyReusable, time.Hour, nil, types.SetupKeyUnlimitedUsage, userID, false, false)
	assert.NoError(t, err)

	// revoke the key
	updateKey := key.Copy()
	updateKey.Revoked = true
	_, err = manager.SaveSetupKey(context.Background(), account.Id, updateKey, userID)
	assert.NoError(t, err)

	// re-activate revoked key
	updateKey.Revoked = false
	_, err = manager.SaveSetupKey(context.Background(), account.Id, updateKey, userID)
	assert.Error(t, err, "should not allow to update revoked key")

}
