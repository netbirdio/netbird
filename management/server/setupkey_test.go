package server

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestGenerateDefaultSetupKey(t *testing.T) {
	expectedName := "Default key"
	expectedRevoke := false
	expectedType := "reusable"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now()
	expectedExpiresAt := time.Now().Add(24 * 30 * time.Hour)

	key := GenerateDefaultSetupKey()

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt, expectedExpiresAt)

}

func TestGenerateSetupKey(t *testing.T) {
	expectedName := "key"
	expectedRevoke := false
	expectedType := "one-off"
	expectedUsedTimes := 0
	expectedCreatedAt := time.Now()
	expectedExpiresAt := time.Now().Add(time.Hour)

	key := GenerateSetupKey(expectedName, SetupKeyOneOff, time.Hour)

	assertKey(t, key, expectedName, expectedRevoke, expectedType, expectedUsedTimes, expectedCreatedAt, expectedExpiresAt)

}

func TestSetupKey_IsValid(t *testing.T) {
	validKey := GenerateSetupKey("valid key", SetupKeyOneOff, time.Hour)
	if !validKey.IsValid() {
		t.Errorf("expected key to be valid, got invalid %v", validKey)
	}

	// expired
	expiredKey := GenerateSetupKey("invalid key", SetupKeyOneOff, -time.Hour)
	if expiredKey.IsValid() {
		t.Errorf("expected key to be invalid due to expiration, got valid %v", expiredKey)
	}

	// revoked
	revokedKey := GenerateSetupKey("invalid key", SetupKeyOneOff, time.Hour)
	revokedKey.Revoked = true
	if revokedKey.IsValid() {
		t.Errorf("expected revoked key to be invalid, got valid %v", revokedKey)
	}

	// overused
	overUsedKey := GenerateSetupKey("invalid key", SetupKeyOneOff, time.Hour)
	overUsedKey.UsedTimes = 1
	if overUsedKey.IsValid() {
		t.Errorf("expected overused key to be invalid, got valid %v", overUsedKey)
	}

	// overused
	reusableKey := GenerateSetupKey("valid key", SetupKeyReusable, time.Hour)
	reusableKey.UsedTimes = 99
	if !reusableKey.IsValid() {
		t.Errorf("expected reusable key to be valid when used many times, got valid %v", reusableKey)
	}
}

func assertKey(t *testing.T, key *SetupKey, expectedName string, expectedRevoke bool, expectedType string, expectedUsedTimes int, expectedCreatedAt time.Time, expectedExpiresAt time.Time) {
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

	if key.CreatedAt.Sub(expectedCreatedAt).Round(time.Hour) != 0 {
		t.Errorf("expected setup key to have CreatedAt ~ %v, got %v", expectedCreatedAt, key.CreatedAt)
	}

	_, err := uuid.Parse(key.Key)
	if err != nil {
		t.Errorf("expected key to be a valid UUID, got %v, %v", key.Key, err)
	}
}
