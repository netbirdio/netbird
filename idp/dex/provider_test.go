package dex

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dexidp/dex/storage"
	sqllib "github.com/dexidp/dex/storage/sql"
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

// openTestStorage creates a SQLite storage in the given directory for testing.
func openTestStorage(t *testing.T, tmpDir string) storage.Storage {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	stor, err := (&sqllib.SQLite3{File: filepath.Join(tmpDir, "dex.db")}).Open(logger)
	require.NoError(t, err)
	return stor
}

func TestStaticConnectors_CreatedFromYAML(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "dex-static-conn-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	yamlContent := `
issuer: http://localhost:5556/dex
storage:
  type: sqlite3
  config:
    file: ` + filepath.Join(tmpDir, "dex.db") + `
web:
  http: 127.0.0.1:5556
enablePasswordDB: true
connectors:
- type: oidc
  id: my-oidc
  name: My OIDC Provider
  config:
    issuer: https://accounts.example.com
    clientID: test-client-id
    clientSecret: test-client-secret
    redirectURI: http://localhost:5556/dex/callback
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	yamlConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Open storage and run initializeStorage directly (avoids Dex server
	// trying to dial the OIDC issuer)
	stor := openTestStorage(t, tmpDir)
	defer stor.Close()

	err = initializeStorage(ctx, stor, yamlConfig)
	require.NoError(t, err)

	// Verify connector was created in storage
	conn, err := stor.GetConnector(ctx, "my-oidc")
	require.NoError(t, err)
	assert.Equal(t, "my-oidc", conn.ID)
	assert.Equal(t, "My OIDC Provider", conn.Name)
	assert.Equal(t, "oidc", conn.Type)

	// Verify config fields were serialized correctly
	var configMap map[string]interface{}
	err = json.Unmarshal(conn.Config, &configMap)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.example.com", configMap["issuer"])
	assert.Equal(t, "test-client-id", configMap["clientID"])
}

func TestStaticConnectors_UpdatedOnRestart(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "dex-static-conn-update-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbFile := filepath.Join(tmpDir, "dex.db")

	// First: load config with initial connector
	yamlContent1 := `
issuer: http://localhost:5556/dex
storage:
  type: sqlite3
  config:
    file: ` + dbFile + `
web:
  http: 127.0.0.1:5556
enablePasswordDB: true
connectors:
- type: oidc
  id: my-oidc
  name: Original Name
  config:
    issuer: https://accounts.example.com
    clientID: original-client-id
    clientSecret: original-secret
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(yamlContent1), 0644)
	require.NoError(t, err)

	yamlConfig1, err := LoadConfig(configPath)
	require.NoError(t, err)

	stor := openTestStorage(t, tmpDir)
	err = initializeStorage(ctx, stor, yamlConfig1)
	require.NoError(t, err)

	// Verify initial state
	conn, err := stor.GetConnector(ctx, "my-oidc")
	require.NoError(t, err)
	assert.Equal(t, "Original Name", conn.Name)

	var configMap1 map[string]interface{}
	err = json.Unmarshal(conn.Config, &configMap1)
	require.NoError(t, err)
	assert.Equal(t, "original-client-id", configMap1["clientID"])

	// Close storage to simulate restart
	stor.Close()

	// Second: load updated config against the same DB
	yamlContent2 := `
issuer: http://localhost:5556/dex
storage:
  type: sqlite3
  config:
    file: ` + dbFile + `
web:
  http: 127.0.0.1:5556
enablePasswordDB: true
connectors:
- type: oidc
  id: my-oidc
  name: Updated Name
  config:
    issuer: https://accounts.example.com
    clientID: updated-client-id
    clientSecret: updated-secret
`
	err = os.WriteFile(configPath, []byte(yamlContent2), 0644)
	require.NoError(t, err)

	yamlConfig2, err := LoadConfig(configPath)
	require.NoError(t, err)

	stor2 := openTestStorage(t, tmpDir)
	defer stor2.Close()

	err = initializeStorage(ctx, stor2, yamlConfig2)
	require.NoError(t, err)

	// Verify connector was updated, not duplicated
	allConnectors, err := stor2.ListConnectors(ctx)
	require.NoError(t, err)

	nonLocalCount := 0
	for _, c := range allConnectors {
		if c.ID != "local" {
			nonLocalCount++
		}
	}
	assert.Equal(t, 1, nonLocalCount, "connector should be updated, not duplicated")

	conn2, err := stor2.GetConnector(ctx, "my-oidc")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", conn2.Name)

	var configMap2 map[string]interface{}
	err = json.Unmarshal(conn2.Config, &configMap2)
	require.NoError(t, err)
	assert.Equal(t, "updated-client-id", configMap2["clientID"])
}

func TestStaticConnectors_MultipleConnectors(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "dex-static-conn-multi-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	yamlContent := `
issuer: http://localhost:5556/dex
storage:
  type: sqlite3
  config:
    file: ` + filepath.Join(tmpDir, "dex.db") + `
web:
  http: 127.0.0.1:5556
enablePasswordDB: true
connectors:
- type: oidc
  id: my-oidc
  name: My OIDC Provider
  config:
    issuer: https://accounts.example.com
    clientID: oidc-client-id
    clientSecret: oidc-secret
- type: google
  id: my-google
  name: Google Login
  config:
    clientID: google-client-id
    clientSecret: google-secret
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	yamlConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	stor := openTestStorage(t, tmpDir)
	defer stor.Close()

	err = initializeStorage(ctx, stor, yamlConfig)
	require.NoError(t, err)

	allConnectors, err := stor.ListConnectors(ctx)
	require.NoError(t, err)

	// Build a map for easier assertion
	connByID := make(map[string]storage.Connector)
	for _, c := range allConnectors {
		connByID[c.ID] = c
	}

	// Verify both static connectors exist
	oidcConn, ok := connByID["my-oidc"]
	require.True(t, ok, "oidc connector should exist")
	assert.Equal(t, "My OIDC Provider", oidcConn.Name)
	assert.Equal(t, "oidc", oidcConn.Type)

	var oidcConfig map[string]interface{}
	err = json.Unmarshal(oidcConn.Config, &oidcConfig)
	require.NoError(t, err)
	assert.Equal(t, "oidc-client-id", oidcConfig["clientID"])

	googleConn, ok := connByID["my-google"]
	require.True(t, ok, "google connector should exist")
	assert.Equal(t, "Google Login", googleConn.Name)
	assert.Equal(t, "google", googleConn.Type)

	var googleConfig map[string]interface{}
	err = json.Unmarshal(googleConn.Config, &googleConfig)
	require.NoError(t, err)
	assert.Equal(t, "google-client-id", googleConfig["clientID"])

	// Verify local connector still exists alongside them (enablePasswordDB: true)
	localConn, ok := connByID["local"]
	require.True(t, ok, "local connector should exist")
	assert.Equal(t, "local", localConn.Type)
}

func TestStaticConnectors_EmptyList(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "dex-static-conn-empty-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

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

	yamlConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	provider, err := NewProviderFromYAML(ctx, yamlConfig)
	require.NoError(t, err)
	defer func() { _ = provider.Stop(ctx) }()

	// No static connectors configured, so ListConnectors should return empty
	connectors, err := provider.ListConnectors(ctx)
	require.NoError(t, err)
	assert.Empty(t, connectors)

	// But local connector should still exist
	localConn, err := provider.Storage().GetConnector(ctx, "local")
	require.NoError(t, err)
	assert.Equal(t, "local", localConn.ID)
}

func TestNewProvider_ContinueOnConnectorFailure(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "dex-connector-failure-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &Config{
		Issuer:  "http://localhost:5556/dex",
		Port:    5556,
		DataDir: tmpDir,
	}

	provider, err := NewProvider(ctx, config)
	require.NoError(t, err)
	defer func() { _ = provider.Stop(ctx) }()

	// The provider should have started successfully even though
	// ContinueOnConnectorFailure is an internal Dex config field.
	// We verify the provider is functional by performing a basic operation.
	assert.NotNil(t, provider.dexServer)
	assert.NotNil(t, provider.storage)
}

func TestBuildDexConfig_ContinueOnConnectorFailure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dex-build-config-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

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

	yamlConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	ctx := context.Background()
	stor, err := yamlConfig.Storage.OpenStorage(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)
	defer stor.Close()

	err = initializeStorage(ctx, stor, yamlConfig)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := buildDexConfig(yamlConfig, stor, logger)

	assert.True(t, cfg.ContinueOnConnectorFailure,
		"buildDexConfig must set ContinueOnConnectorFailure to true so management starts even if an external IdP is down")
}
