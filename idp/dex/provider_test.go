package dex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCreationFlow(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "dex-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create provider with minimal config
	config := &Config{
		Issuer:  "http://localhost:5556/dex",
		Port:    5556,
		DataDir: tmpDir,
	}

	provider, err := NewProvider(ctx, config)
	require.NoError(t, err)
	defer func() { _ = provider.Stop(ctx) }()

	// Test user data
	email := "test@example.com"
	username := "testuser"
	password := "testpassword123"

	// Create the user
	encodedID, err := provider.CreateUser(ctx, email, username, password)
	require.NoError(t, err)
	require.NotEmpty(t, encodedID)

	t.Logf("Created user with encoded ID: %s", encodedID)

	// Verify the encoded ID can be decoded
	rawUserID, connectorID, err := DecodeDexUserID(encodedID)
	require.NoError(t, err)
	assert.NotEmpty(t, rawUserID)
	assert.Equal(t, "local", connectorID)

	t.Logf("Decoded: rawUserID=%s, connectorID=%s", rawUserID, connectorID)

	// Verify we can look up the user by encoded ID
	user, err := provider.GetUserByID(ctx, encodedID)
	require.NoError(t, err)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, rawUserID, user.UserID)

	// Verify we can also look up by raw UUID (backwards compatibility)
	user2, err := provider.GetUserByID(ctx, rawUserID)
	require.NoError(t, err)
	assert.Equal(t, email, user2.Email)

	// Verify we can look up by email
	user3, err := provider.GetUser(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, rawUserID, user3.UserID)

	// Verify encoding produces consistent format
	reEncodedID := EncodeDexUserID(rawUserID, "local")
	assert.Equal(t, encodedID, reEncodedID)
}

func TestDecodeDexUserID(t *testing.T) {
	tests := []struct {
		name       string
		encodedID  string
		wantUserID string
		wantConnID string
		wantErr    bool
	}{
		{
			name:       "valid encoded ID",
			encodedID:  "CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs",
			wantUserID: "7aad8c05-3287-473f-b42a-365504bf25e7",
			wantConnID: "local",
			wantErr:    false,
		},
		{
			name:       "invalid base64",
			encodedID:  "not-valid-base64!!!",
			wantUserID: "",
			wantConnID: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, connID, err := DecodeDexUserID(tt.encodedID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUserID, userID)
			assert.Equal(t, tt.wantConnID, connID)
		})
	}
}

func TestEncodeDexUserID(t *testing.T) {
	userID := "7aad8c05-3287-473f-b42a-365504bf25e7"
	connectorID := "local"

	encoded := EncodeDexUserID(userID, connectorID)
	assert.NotEmpty(t, encoded)

	// Verify round-trip
	decodedUserID, decodedConnID, err := DecodeDexUserID(encoded)
	require.NoError(t, err)
	assert.Equal(t, userID, decodedUserID)
	assert.Equal(t, connectorID, decodedConnID)
}

func TestEncodeDexUserID_MatchesDexFormat(t *testing.T) {
	// This is an actual ID from Dex - verify our encoding matches
	knownEncodedID := "CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs"
	knownUserID := "7aad8c05-3287-473f-b42a-365504bf25e7"
	knownConnectorID := "local"

	// Decode the known ID
	userID, connID, err := DecodeDexUserID(knownEncodedID)
	require.NoError(t, err)
	assert.Equal(t, knownUserID, userID)
	assert.Equal(t, knownConnectorID, connID)

	// Re-encode and verify it matches
	reEncoded := EncodeDexUserID(knownUserID, knownConnectorID)
	assert.Equal(t, knownEncodedID, reEncoded)
}

func TestCreateUserInTempDB(t *testing.T) {
	ctx := context.Background()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "dex-create-user-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create YAML config for the test
	yamlContent := `
issuer: http://localhost:5556/dex
storage:
  type: sqlite3
  config:
    file: ` + filepath.Join(tmpDir, "dex.db") + `
web:
  http: 127.0.0.1:5556
enablePasswordDB: true
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Load config and create provider
	yamlConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	provider, err := NewProviderFromYAML(ctx, yamlConfig)
	require.NoError(t, err)
	defer func() { _ = provider.Stop(ctx) }()

	// Create user
	email := "newuser@example.com"
	username := "newuser"
	password := "securepassword123"

	encodedID, err := provider.CreateUser(ctx, email, username, password)
	require.NoError(t, err)

	t.Logf("Created user: email=%s, encodedID=%s", email, encodedID)

	// Verify lookup works with encoded ID
	user, err := provider.GetUserByID(ctx, encodedID)
	require.NoError(t, err)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, username, user.Username)

	// Decode and verify format
	rawID, connID, err := DecodeDexUserID(encodedID)
	require.NoError(t, err)
	assert.Equal(t, "local", connID)
	assert.Equal(t, rawID, user.UserID)

	t.Logf("User lookup successful: rawID=%s, connectorID=%s", rawID, connID)
}
