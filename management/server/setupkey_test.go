package server

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
	"time"
)

func TestDefaultAccountManager_SaveSetupKey(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "test_user"
	account, err := manager.GetOrCreateAccountByUser(userID, "")
	if err != nil {
		t.Fatal(err)
	}

	err = manager.SaveGroup(account.Id, userID, &Group{
		ID:    "group_1",
		Name:  "group_name_1",
		Peers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	expiresIn := time.Hour
	keyName := "my-test-key"

	key, err := manager.CreateSetupKey(account.Id, keyName, SetupKeyReusable, expiresIn, []string{},
		SetupKeyUnlimitedUsage, userID)
	if err != nil {
		t.Fatal(err)
	}

	autoGroups := []string{"group_1", "group_2"}
	newKeyName := "my-new-test-key"
	revoked := true
	newKey, err := manager.SaveSetupKey(account.Id, &SetupKey{
		Id:         key.Id,
		Name:       newKeyName,
		Revoked:    revoked,
		AutoGroups: autoGroups,
	}, userID)
	if err != nil {
		t.Fatal(err)
	}

	assertKey(t, newKey, newKeyName, revoked, "reusable", 0, key.CreatedAt, key.ExpiresAt,
		key.Id, time.Now(), autoGroups)

	events, err := manager.GetEvents(account.Id, userID)
	if err != nil {
		return
	}

	var ev *activity.Event
	for _, event := range events {
		if event.Activity == activity.SetupKeyRevoked {
			ev = event
		}
	}

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, newKeyName, ev.Meta["name"])
	assert.Equal(t, fmt.Sprint(key.Type), fmt.Sprint(ev.Meta["type"]))
	assert.NotEmpty(t, ev.Meta["key"])
	assert.Equal(t, userID, ev.InitiatorID)
	assert.Equal(t, key.Id, ev.TargetID)
}

func TestDefaultAccountManager_CreateSetupKey(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	userID := "test_user"
	account, err := manager.GetOrCreateAccountByUser(userID, "")
	if err != nil {
		t.Fatal(err)
	}

	err = manager.SaveGroup(account.Id, userID, &Group{
		ID:    "group_1",
		Name:  "group_name_1",
		Peers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.SaveGroup(account.Id, userID, &Group{
		ID:    "group_2",
		Name:  "group_name_2",
		Peers: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	type testCase struct {
		name string

		expectedKeyName   string
		expectedUsedTimes int
		expectedType      string
		expectedGroups    []string
		expectedCreatedAt time.Time
		expectedUpdatedAt time.Time
		expectedExpiresAt time.Time
		expectedFailure   bool //indicates whether key creation should fail
	}

	now := time.Now()
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

	for _, tCase := range []testCase{testCase1, testCase2} {
		t.Run(tCase.name, func(t *testing.T) {
			key, err := manager.CreateSetupKey(account.Id, tCase.expectedKeyName, SetupKeyReusable, expiresIn,
				tCase.expectedGroups, SetupKeyUnlimitedUsage, userID)

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
				tCase.expectedCreatedAt, tCase.expectedExpiresAt, strconv.Itoa(int(Hash(key.Key))),
				tCase.expectedUpdatedAt, tCase.expectedGroups)

			events, err := manager.GetEvents(account.Id, userID)
			if err != nil {
				return
			}

			var ev *activity.Event
			for _, event := range events {
				if event.Activity == activity.SetupKeyCreated {
					ev = event
				}
			}

			assert.NotNil(t, ev)
			assert.Equal(t, account.Id, ev.AccountID)
			assert.Equal(t, tCase.expectedKeyName, ev.Meta["name"])
			assert.Equal(t, tCase.expectedType, fmt.Sprint(ev.Meta["type"]))
			assert.NotEmpty(t, ev.Meta["key"])
		})
	}

}

func TestGenerateDefaultSetupKey(t *testing.T) {
	expectedName := "Default key"
	expectedRevoke := false
	expectedType := "reusable"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now()
	expectedUpdatedAt := time.Now()
	expectedExpiresAt := time.Now().Add(24 * 30 * time.Hour)
	var expectedAutoGroups []string

	key := GenerateDefaultSetupKey()

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt,
		expectedExpiresAt, strconv.Itoa(int(Hash(key.Key))), expectedUpdatedAt, expectedAutoGroups)

}

func TestGenerateSetupKey(t *testing.T) {
	expectedName := "key"
	expectedRevoke := false
	expectedType := "one-off"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now()
	expectedExpiresAt := time.Now().Add(time.Hour)
	expectedUpdatedAt := time.Now()
	var expectedAutoGroups []string

	key := GenerateSetupKey(expectedName, SetupKeyOneOff, time.Hour, []string{}, SetupKeyUnlimitedUsage)

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt,
		expectedExpiresAt, strconv.Itoa(int(Hash(key.Key))), expectedUpdatedAt, expectedAutoGroups)

}

func TestSetupKey_IsValid(t *testing.T) {
	validKey := GenerateSetupKey("valid key", SetupKeyOneOff, time.Hour, []string{}, SetupKeyUnlimitedUsage)
	if !validKey.IsValid() {
		t.Errorf("expected key to be valid, got invalid %v", validKey)
	}

	// expired
	expiredKey := GenerateSetupKey("invalid key", SetupKeyOneOff, -time.Hour, []string{}, SetupKeyUnlimitedUsage)
	if expiredKey.IsValid() {
		t.Errorf("expected key to be invalid due to expiration, got valid %v", expiredKey)
	}

	// revoked
	revokedKey := GenerateSetupKey("invalid key", SetupKeyOneOff, time.Hour, []string{}, SetupKeyUnlimitedUsage)
	revokedKey.Revoked = true
	if revokedKey.IsValid() {
		t.Errorf("expected revoked key to be invalid, got valid %v", revokedKey)
	}

	// overused
	overUsedKey := GenerateSetupKey("invalid key", SetupKeyOneOff, time.Hour, []string{}, SetupKeyUnlimitedUsage)
	overUsedKey.UsedTimes = 1
	if overUsedKey.IsValid() {
		t.Errorf("expected overused key to be invalid, got valid %v", overUsedKey)
	}

	// overused
	reusableKey := GenerateSetupKey("valid key", SetupKeyReusable, time.Hour, []string{}, SetupKeyUnlimitedUsage)
	reusableKey.UsedTimes = 99
	if !reusableKey.IsValid() {
		t.Errorf("expected reusable key to be valid when used many times, got valid %v", reusableKey)
	}
}

func assertKey(t *testing.T, key *SetupKey, expectedName string, expectedRevoke bool, expectedType string,
	expectedUsedTimes int, expectedCreatedAt time.Time, expectedExpiresAt time.Time, expectedID string,
	expectedUpdatedAt time.Time, expectedAutoGroups []string) {
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

	if key.ExpiresAt.Sub(expectedExpiresAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have ExpiresAt ~ %v, got %v", expectedExpiresAt, key.ExpiresAt)
	}

	if key.UpdatedAt.Sub(expectedUpdatedAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have UpdatedAt ~ %v, got %v", expectedUpdatedAt, key.UpdatedAt)
	}

	if key.CreatedAt.Sub(expectedCreatedAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have CreatedAt ~ %v, got %v", expectedCreatedAt, key.CreatedAt)
	}

	_, err := uuid.Parse(key.Key)
	if err != nil {
		t.Errorf("expected key to be a valid UUID, got %v, %v", key.Key, err)
	}

	if key.Id != strconv.Itoa(int(Hash(key.Key))) {
		t.Errorf("expected key Id t= %v, got %v", expectedID, key.Id)
	}

	if len(key.AutoGroups) != len(expectedAutoGroups) {
		t.Errorf("expected key AutoGroups size=%d, got %d", len(expectedAutoGroups), len(key.AutoGroups))
	}
	assert.ElementsMatch(t, key.AutoGroups, expectedAutoGroups, "expected key AutoGroups to be equal")
}

func TestSetupKey_Copy(t *testing.T) {

	key := GenerateSetupKey("key name", SetupKeyOneOff, time.Hour, []string{}, SetupKeyUnlimitedUsage)
	keyCopy := key.Copy()

	assertKey(t, keyCopy, key.Name, key.Revoked, string(key.Type), key.UsedTimes, key.CreatedAt, key.ExpiresAt, key.Id,
		key.UpdatedAt, key.AutoGroups)

}
