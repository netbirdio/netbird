package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/secretenc"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestSqlStore_GetTrustedCAByCRLToken verifies token-based CA lookup.
func TestSqlStore_GetTrustedCAByCRLToken(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	sqlStore := store.(*SqlStore)

	token := "abc123hextoken"
	ca := &types.TrustedCA{
		ID:        "ca-token-test",
		AccountID: "acc-token",
		Name:      "Token CA",
		CRLToken:  &token,
	}
	require.NoError(t, sqlStore.SaveTrustedCA(context.Background(), LockingStrengthUpdate, ca))

	found, err := sqlStore.GetTrustedCAByCRLToken(context.Background(), "abc123hextoken")
	require.NoError(t, err)
	assert.Equal(t, "ca-token-test", found.ID)

	_, err = sqlStore.GetTrustedCAByCRLToken(context.Background(), "notexist")
	require.Error(t, err, "unknown token should return error")
}

// TestSqlStore_TrustedCA_KeyPEMEncryption verifies that KeyPEM is encrypted on save
// and decrypted on load — round-trip with NoOpKeyProvider preserves the value.
func TestSqlStore_TrustedCA_KeyPEMEncryption(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	sqlStore := store.(*SqlStore)
	sqlStore.kp = secretenc.NewNoOpKeyProvider()

	ca := &types.TrustedCA{
		ID:        "test-ca-id",
		AccountID: "test-account",
		Name:      "Test CA",
		KeyPEM:    "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----",
	}
	require.NoError(t, sqlStore.SaveTrustedCA(context.Background(), LockingStrengthUpdate, ca))

	loaded, err := sqlStore.GetTrustedCAByID(context.Background(), LockingStrengthNone, "test-account", "test-ca-id")
	require.NoError(t, err)
	assert.Equal(t, ca.KeyPEM, loaded.KeyPEM)
}

// TestSqlStore_TrustedCA_EmptyKeyPEM verifies that empty KeyPEM is left unchanged.
func TestSqlStore_TrustedCA_EmptyKeyPEM(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	sqlStore := store.(*SqlStore)
	sqlStore.kp = secretenc.NewNoOpKeyProvider()

	ca := &types.TrustedCA{
		ID:        "test-ca-empty",
		AccountID: "test-account",
		Name:      "Empty Key CA",
		KeyPEM:    "",
	}
	require.NoError(t, sqlStore.SaveTrustedCA(context.Background(), LockingStrengthUpdate, ca))

	loaded, err := sqlStore.GetTrustedCAByID(context.Background(), LockingStrengthNone, "test-account", "test-ca-empty")
	require.NoError(t, err)
	assert.Equal(t, "", loaded.KeyPEM)
}

// TestSqlStore_TrustedCA_ListDecryption verifies ListTrustedCAs decrypts all entries.
func TestSqlStore_TrustedCA_ListDecryption(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	sqlStore := store.(*SqlStore)
	sqlStore.kp = secretenc.NewNoOpKeyProvider()

	for i := 0; i < 3; i++ {
		ca := &types.TrustedCA{
			ID:        "list-ca-" + string(rune('0'+i)),
			AccountID: "list-account",
			Name:      "CA",
			KeyPEM:    "secret-key",
		}
		require.NoError(t, sqlStore.SaveTrustedCA(context.Background(), LockingStrengthUpdate, ca))
	}

	cas, err := sqlStore.ListTrustedCAs(context.Background(), LockingStrengthNone, "list-account")
	require.NoError(t, err)
	assert.Len(t, cas, 3)
	for _, ca := range cas {
		assert.Equal(t, "secret-key", ca.KeyPEM)
	}
}

// TestSqlStore_TrustedCA_DoNotMutateCaller verifies that SaveTrustedCA does not mutate
// the caller's TrustedCA struct.
func TestSqlStore_TrustedCA_DoNotMutateCaller(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	sqlStore := store.(*SqlStore)
	sqlStore.kp = secretenc.NewNoOpKeyProvider()

	original := "-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----"
	ca := &types.TrustedCA{
		ID:        "test-nomutate",
		AccountID: "test-account",
		Name:      "Test",
		KeyPEM:    original,
	}
	require.NoError(t, sqlStore.SaveTrustedCA(context.Background(), LockingStrengthUpdate, ca))
	assert.Equal(t, original, ca.KeyPEM, "SaveTrustedCA must not mutate caller's value")
}

// TestSqlStore_DeviceAuthEncryption_VaultRoundTrip verifies that the encrypt/decrypt helpers
// preserve vault token through a round-trip using NoOpKeyProvider.
func TestSqlStore_DeviceAuthEncryption_VaultRoundTrip(t *testing.T) {
	s := &SqlStore{kp: secretenc.NewNoOpKeyProvider()}

	vaultCfg := map[string]string{
		"address": "https://vault.example.com",
		"token":   "my-secret-token",
		"mount":   "pki",
	}
	vaultJSON, err := json.Marshal(vaultCfg)
	require.NoError(t, err)

	d := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeVault,
		CAConfig: string(vaultJSON),
	}

	enc, err := s.encryptDeviceAuthSecrets(d)
	require.NoError(t, err)

	// Original must not be mutated.
	assert.Equal(t, string(vaultJSON), d.CAConfig)

	// Decrypted value must match original.
	require.NoError(t, s.decryptDeviceAuthSecrets(enc))
	var result map[string]string
	require.NoError(t, json.Unmarshal([]byte(enc.CAConfig), &result))
	assert.Equal(t, "my-secret-token", result["token"])
}

// TestSqlStore_DeviceAuthEncryption_PlaintextBackwardCompat verifies that pre-encryption
// plaintext configs (no enc: prefix) are left unchanged by decryptDeviceAuthSecrets.
func TestSqlStore_DeviceAuthEncryption_PlaintextBackwardCompat(t *testing.T) {
	s := &SqlStore{kp: secretenc.NewNoOpKeyProvider()}

	plainCfg := `{"token":"raw-plaintext-token","address":"https://v.example.com"}`
	d := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeVault,
		CAConfig: plainCfg,
	}

	require.NoError(t, s.decryptDeviceAuthSecrets(d))
	// Value should be unchanged — no enc: prefix means pre-encryption plaintext.
	assert.Equal(t, plainCfg, d.CAConfig)
}

// TestSqlStore_DeviceAuthEncryption_EmptyConfig verifies that empty CA config is a no-op.
func TestSqlStore_DeviceAuthEncryption_EmptyConfig(t *testing.T) {
	s := &SqlStore{kp: secretenc.NewNoOpKeyProvider()}
	d := &types.DeviceAuthSettings{CAType: types.DeviceAuthCATypeVault, CAConfig: ""}

	enc, err := s.encryptDeviceAuthSecrets(d)
	require.NoError(t, err)
	assert.Equal(t, "", enc.CAConfig)
}
