package idp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
)

func TestEmbeddedIdPManager_CreateUser_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create the embedded IDP config
	config := &EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: EmbeddedStorageTypeConfig{
				File: filepath.Join(tmpDir, "dex.db"),
			},
		},
	}

	// Create the embedded IDP manager
	manager, err := NewEmbeddedIdPManager(ctx, config, nil)
	require.NoError(t, err)
	defer func() { _ = manager.Stop(ctx) }()

	// Test data
	email := "newuser@example.com"
	name := "New User"
	accountID := "test-account-id"
	invitedByEmail := "admin@example.com"

	// Create the user
	userData, err := manager.CreateUser(ctx, email, name, accountID, invitedByEmail)
	require.NoError(t, err)
	require.NotNil(t, userData)

	t.Logf("Created user: ID=%s, Email=%s, Name=%s, Password=%s",
		userData.ID, userData.Email, userData.Name, userData.Password)

	// Verify user data
	assert.Equal(t, email, userData.Email)
	assert.Equal(t, name, userData.Name)
	assert.NotEmpty(t, userData.ID)
	assert.NotEmpty(t, userData.Password)
	assert.Equal(t, accountID, userData.AppMetadata.WTAccountID)
	assert.Equal(t, invitedByEmail, userData.AppMetadata.WTInvitedBy)

	// Verify the user ID is in Dex's encoded format (base64 protobuf)
	rawUserID, connectorID, err := dex.DecodeDexUserID(userData.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, rawUserID)
	assert.Equal(t, "local", connectorID)

	t.Logf("Decoded user ID: rawUserID=%s, connectorID=%s", rawUserID, connectorID)

	// Verify we can look up the user by the encoded ID
	lookedUpUser, err := manager.GetUserDataByID(ctx, userData.ID, AppMetadata{WTAccountID: accountID})
	require.NoError(t, err)
	assert.Equal(t, email, lookedUpUser.Email)

	// Verify we can look up by email
	users, err := manager.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, email, users[0].Email)

	// Verify creating duplicate user fails
	_, err = manager.CreateUser(ctx, email, name, accountID, invitedByEmail)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestEmbeddedIdPManager_GetUserDataByID_WithEncodedID(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: EmbeddedStorageTypeConfig{
				File: filepath.Join(tmpDir, "dex.db"),
			},
		},
	}

	manager, err := NewEmbeddedIdPManager(ctx, config, nil)
	require.NoError(t, err)
	defer func() { _ = manager.Stop(ctx) }()

	// Create a user first
	userData, err := manager.CreateUser(ctx, "test@example.com", "Test User", "account1", "admin@example.com")
	require.NoError(t, err)

	// The returned ID should be encoded
	encodedID := userData.ID

	// Lookup should work with the encoded ID
	lookedUp, err := manager.GetUserDataByID(ctx, encodedID, AppMetadata{WTAccountID: "account1"})
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", lookedUp.Email)
	assert.Equal(t, "Test User", lookedUp.Name)
}

func TestEmbeddedIdPManager_DeleteUser(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: EmbeddedStorageTypeConfig{
				File: filepath.Join(tmpDir, "dex.db"),
			},
		},
	}

	manager, err := NewEmbeddedIdPManager(ctx, config, nil)
	require.NoError(t, err)
	defer func() { _ = manager.Stop(ctx) }()

	// Create a user
	userData, err := manager.CreateUser(ctx, "delete-me@example.com", "Delete Me", "account1", "admin@example.com")
	require.NoError(t, err)

	// Delete the user using the encoded ID
	err = manager.DeleteUser(ctx, userData.ID)
	require.NoError(t, err)

	// Verify user no longer exists
	_, err = manager.GetUserDataByID(ctx, userData.ID, AppMetadata{})
	assert.Error(t, err)
}

func TestEmbeddedIdPManager_GetAccount(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: EmbeddedStorageTypeConfig{
				File: filepath.Join(tmpDir, "dex.db"),
			},
		},
	}

	manager, err := NewEmbeddedIdPManager(ctx, config, nil)
	require.NoError(t, err)
	defer func() { _ = manager.Stop(ctx) }()

	// Create multiple users
	_, err = manager.CreateUser(ctx, "user1@example.com", "User 1", "account1", "admin@example.com")
	require.NoError(t, err)

	_, err = manager.CreateUser(ctx, "user2@example.com", "User 2", "account1", "admin@example.com")
	require.NoError(t, err)

	// Get all users for the account
	users, err := manager.GetAccount(ctx, "account1")
	require.NoError(t, err)
	assert.Len(t, users, 2)

	emails := make([]string, len(users))
	for i, u := range users {
		emails[i] = u.Email
	}
	assert.Contains(t, emails, "user1@example.com")
	assert.Contains(t, emails, "user2@example.com")
}

func TestEmbeddedIdPManager_UserIDFormat_MatchesJWT(t *testing.T) {
	// This test verifies that the user ID returned by CreateUser
	// matches the format that Dex uses in JWT tokens (the 'sub' claim)
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: EmbeddedStorageTypeConfig{
				File: filepath.Join(tmpDir, "dex.db"),
			},
		},
	}

	manager, err := NewEmbeddedIdPManager(ctx, config, nil)
	require.NoError(t, err)
	defer func() { _ = manager.Stop(ctx) }()

	// Create a user
	userData, err := manager.CreateUser(ctx, "jwt-test@example.com", "JWT Test", "account1", "admin@example.com")
	require.NoError(t, err)

	// The ID should be in the format: base64(protobuf{user_id, connector_id})
	// Example: CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs

	// Verify it can be decoded
	rawUserID, connectorID, err := dex.DecodeDexUserID(userData.ID)
	require.NoError(t, err)

	// Raw user ID should be a UUID
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, rawUserID)

	// Connector ID should be "local" for password-based auth
	assert.Equal(t, "local", connectorID)

	// Re-encoding should produce the same result
	reEncoded := dex.EncodeDexUserID(rawUserID, connectorID)
	assert.Equal(t, userData.ID, reEncoded)

	t.Logf("User ID format verified:")
	t.Logf("  Encoded ID: %s", userData.ID)
	t.Logf("  Raw UUID:   %s", rawUserID)
	t.Logf("  Connector:  %s", connectorID)
}

func TestEmbeddedIdPManager_GetLocalKeysLocation(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "embedded-idp-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name         string
		localAddress string
		expected     string
	}{
		{
			name:         "localhost with port",
			localAddress: "localhost:8080",
			expected:     "http://localhost:8080/oauth2/keys",
		},
		{
			name:         "localhost with https port",
			localAddress: "localhost:443",
			expected:     "http://localhost:443/oauth2/keys",
		},
		{
			name:         "port only format",
			localAddress: ":8080",
			expected:     "http://localhost:8080/oauth2/keys",
		},
		{
			name:         "empty address",
			localAddress: "",
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &EmbeddedIdPConfig{
				Enabled:      true,
				Issuer:       "http://localhost:5556/dex",
				LocalAddress: tt.localAddress,
				Storage: EmbeddedStorageConfig{
					Type: "sqlite3",
					Config: EmbeddedStorageTypeConfig{
						File: filepath.Join(tmpDir, "dex-"+tt.name+".db"),
					},
				},
			}

			manager, err := NewEmbeddedIdPManager(ctx, config, nil)
			require.NoError(t, err)
			defer func() { _ = manager.Stop(ctx) }()

			result := manager.GetLocalKeysLocation()
			assert.Equal(t, tt.expected, result)
		})
	}
}
