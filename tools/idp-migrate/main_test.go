package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/idp/migration"
)

// TestMigrationServerInterface is a compile-time check that migrationServer
// implements the migration.Server interface.
func TestMigrationServerInterface(t *testing.T) {
	var _ migration.Server = (*migrationServer)(nil)
}

func TestResolveConnector_FlagOverridesEnv(t *testing.T) {
	flagConn := dex.Connector{
		Type: "oidc",
		Name: "from-flag",
		ID:   "flag-id",
		Config: map[string]interface{}{
			"issuer": "https://flag.example.com",
		},
	}
	flagJSON, err := json.Marshal(flagConn)
	require.NoError(t, err)
	flagB64 := base64.StdEncoding.EncodeToString(flagJSON)

	envConn := dex.Connector{
		Type: "oidc",
		Name: "from-env",
		ID:   "env-id",
		Config: map[string]interface{}{
			"issuer": "https://env.example.com",
		},
	}
	envJSON, err := json.Marshal(envConn)
	require.NoError(t, err)
	envB64 := base64.StdEncoding.EncodeToString(envJSON)

	t.Setenv("IDP_SEED_INFO", envB64)

	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "zitadel",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://config.example.com",
				ClientID:     "config-client",
				ClientSecret: "config-secret",
			},
		},
	}

	// Flag takes priority over env and config
	conn, err := resolveConnector(flagB64, cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "flag-id", conn.ID)
	assert.Equal(t, "from-flag", conn.Name)

	// Empty flag → env takes priority over config
	conn, err = resolveConnector("", cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "env-id", conn.ID)
	assert.Equal(t, "from-env", conn.Name)

	// Empty flag + no env → config auto-detect
	t.Setenv("IDP_SEED_INFO", "")
	conn, err = resolveConnector("", cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "zitadel", conn.ID)
}

func TestResolveConnector_InvalidBase64(t *testing.T) {
	cfg := &nbconfig.Config{}
	_, err := resolveConnector("not-valid-base64!!!", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decode")
}

func TestResolveConnector_InvalidJSON(t *testing.T) {
	cfg := &nbconfig.Config{}
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := resolveConnector(encoded, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "json unmarshal")
}

func TestResolveConnector_EmptyConnectorID(t *testing.T) {
	conn := dex.Connector{
		Type: "oidc",
		Name: "no-id",
		ID:   "",
	}
	data, err := json.Marshal(conn)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(data)
	result, err := resolveConnector(encoded, &nbconfig.Config{})
	require.NoError(t, err)
	// resolveConnector returns the connector; caller (run()) checks for empty ID
	assert.Equal(t, "", result.ID)
}

func TestResolveConnector_NoConfigFallback(t *testing.T) {
	t.Setenv("IDP_SEED_INFO", "")

	cfg := &nbconfig.Config{} // no IdpManagerConfig
	conn, err := resolveConnector("", cfg)
	require.NoError(t, err)
	assert.Nil(t, conn) // no connector found
}

func TestBuildConnectorFromConfig_Zitadel(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "zitadel",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://zitadel.example.com",
				ClientID:     "zitadel-client-id",
				ClientSecret: "zitadel-secret",
			},
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "zitadel", conn.Type)
	assert.Equal(t, "zitadel", conn.ID)
	assert.Equal(t, "zitadel", conn.Name)
	assert.Equal(t, "https://zitadel.example.com", conn.Config["issuer"])
	assert.Equal(t, "zitadel-client-id", conn.Config["clientID"])
	assert.Equal(t, "zitadel-secret", conn.Config["clientSecret"])
	assert.Equal(t, "https://zitadel.example.com/oauth2/callback", conn.Config["redirectURI"])
}

func TestBuildConnectorFromConfig_Auth0(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "auth0",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://tenant.auth0.com/",
				ClientID:     "auth0-id",
				ClientSecret: "auth0-secret",
			},
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "oidc", conn.Type) // Auth0 maps to generic OIDC
	assert.Equal(t, "auth0", conn.ID)
	assert.Equal(t, "https://tenant.auth0.com/oauth2/callback", conn.Config["redirectURI"])
}

func TestBuildConnectorFromConfig_Azure(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "azure",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://login.microsoftonline.com/tenant-id/v2.0",
				ClientID:     "azure-id",
				ClientSecret: "azure-secret",
			},
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "entra", conn.Type) // Azure maps to entra
	assert.Equal(t, "azure", conn.ID)
}

func TestBuildConnectorFromConfig_Google(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "google",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://accounts.google.com",
				ClientID:     "google-id",
				ClientSecret: "google-secret",
			},
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "google", conn.Type)
	assert.Equal(t, "google", conn.ID)
}

func TestBuildConnectorFromConfig_JumpCloud(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "jumpcloud",
			ClientConfig: &idp.ClientConfig{
				Issuer:       "https://oauth.id.jumpcloud.com/",
				ClientID:     "jc-id",
				ClientSecret: "jc-secret",
			},
		},
	}

	_, err := buildConnectorFromConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jumpcloud")
}

func TestBuildConnectorFromConfig_MissingClientConfig(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "zitadel",
			// no ClientConfig
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, conn) // returns nil, nil when no ClientConfig
}

func TestBuildConnectorFromConfig_MissingIdpManagerConfig(t *testing.T) {
	cfg := &nbconfig.Config{}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, conn)
}

func TestBuildConnectorFromConfig_IssuerFallbackToHttpConfig(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "keycloak",
			ClientConfig: &idp.ClientConfig{
				// Issuer empty — should fall back to HttpConfig.AuthIssuer
				ClientID:     "kc-id",
				ClientSecret: "kc-secret",
			},
		},
		HttpConfig: &nbconfig.HttpServerConfig{
			AuthIssuer: "https://keycloak.example.com/realms/myrealm",
		},
	}

	conn, err := buildConnectorFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "keycloak", conn.Type)
	assert.Equal(t, "https://keycloak.example.com/realms/myrealm", conn.Config["issuer"])
}

func TestBuildConnectorFromConfig_MissingIssuer(t *testing.T) {
	cfg := &nbconfig.Config{
		IdpManagerConfig: &idp.Config{
			ManagerType: "okta",
			ClientConfig: &idp.ClientConfig{
				ClientID:     "okta-id",
				ClientSecret: "okta-secret",
				// Issuer empty, no HttpConfig either
			},
		},
	}

	_, err := buildConnectorFromConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestMapManagerTypeToConnectorType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"zitadel", "zitadel", false},
		{"keycloak", "keycloak", false},
		{"okta", "okta", false},
		{"authentik", "authentik", false},
		{"pocketid", "pocketid", false},
		{"auth0", "oidc", false},
		{"azure", "entra", false},
		{"google", "google", false},
		{"jumpcloud", "", true},
		{"unknown-provider", "oidc", false}, // fallback to generic OIDC
		{"", "oidc", false},                 // empty also falls through to default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := mapManagerTypeToConnectorType(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		configJSON := `{
			"Datadir": "/var/lib/netbird",
			"DataStoreEncryptionKey": "test-key-1234567890123456",
			"StoreConfig": {
				"Engine": "sqlite"
			},
			"IdpManagerConfig": {
				"ManagerType": "zitadel",
				"ClientConfig": {
					"Issuer": "https://zitadel.example.com",
					"ClientID": "test-client",
					"ClientSecret": "test-secret"
				}
			}
		}`
		require.NoError(t, os.WriteFile(configPath, []byte(configJSON), 0600))

		cfg, err := loadConfig(configPath)
		require.NoError(t, err)
		assert.Equal(t, "/var/lib/netbird", cfg.Datadir)
		assert.Equal(t, "test-key-1234567890123456", cfg.DataStoreEncryptionKey)
		require.NotNil(t, cfg.IdpManagerConfig)
		assert.Equal(t, "zitadel", cfg.IdpManagerConfig.ManagerType)
		assert.Equal(t, "test-client", cfg.IdpManagerConfig.ClientConfig.ClientID)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadConfig("/nonexistent/path/management.json")
		require.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "bad.json")
		require.NoError(t, os.WriteFile(configPath, []byte("{invalid"), 0600))

		_, err := loadConfig(configPath)
		require.Error(t, err)
	})
}

func TestDecodeConnector(t *testing.T) {
	conn := dex.Connector{
		Type: "oidc",
		Name: "test",
		ID:   "test-id",
		Config: map[string]interface{}{
			"issuer":       "https://example.com",
			"clientID":     "cid",
			"clientSecret": "csecret",
		},
	}

	data, err := json.Marshal(conn)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(data)

	result, err := decodeConnector(encoded)
	require.NoError(t, err)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "oidc", result.Type)
	assert.Equal(t, "https://example.com", result.Config["issuer"])
}

func TestDeriveDomain(t *testing.T) {
	t.Run("priority 1: LetsEncryptDomain", func(t *testing.T) {
		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain:  "mgmt.example.com",
				AuthIssuer:         "https://other.example.com/oauth2",
				OIDCConfigEndpoint: "https://oidc.example.com/.well-known/openid-configuration",
			},
		}
		domain, err := deriveDomain(cfg)
		require.NoError(t, err)
		assert.Equal(t, "mgmt.example.com", domain)
	})

	t.Run("priority 2: OIDCConfigEndpoint", func(t *testing.T) {
		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				OIDCConfigEndpoint: "https://oidc.example.com/.well-known/openid-configuration",
				AuthIssuer:         "https://issuer.example.com/oauth2",
			},
		}
		domain, err := deriveDomain(cfg)
		require.NoError(t, err)
		assert.Equal(t, "oidc.example.com", domain)
	})

	t.Run("priority 3: AuthIssuer", func(t *testing.T) {
		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				AuthIssuer: "https://issuer.example.com/oauth2",
			},
		}
		domain, err := deriveDomain(cfg)
		require.NoError(t, err)
		assert.Equal(t, "issuer.example.com", domain)
	})

	t.Run("priority 4: IdpManagerConfig issuer", func(t *testing.T) {
		cfg := &nbconfig.Config{
			IdpManagerConfig: &idp.Config{
				ClientConfig: &idp.ClientConfig{
					Issuer: "https://zitadel.example.com",
				},
			},
		}
		domain, err := deriveDomain(cfg)
		require.NoError(t, err)
		assert.Equal(t, "zitadel.example.com", domain)
	})

	t.Run("error when no domain found", func(t *testing.T) {
		cfg := &nbconfig.Config{}
		_, err := deriveDomain(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not determine domain")
	})
}

func TestHostFromURL(t *testing.T) {
	assert.Equal(t, "example.com", hostFromURL("https://example.com/path"))
	assert.Equal(t, "example.com", hostFromURL("https://example.com:8080/path"))
	assert.Equal(t, "", hostFromURL("not-a-url"))
}

func TestGenerateConfig(t *testing.T) {
	t.Run("generates valid config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		originalConfig := `{
  "Datadir": "/var/lib/netbird",
  "HttpConfig": {
    "LetsEncryptDomain": "mgmt.example.com",
    "AuthIssuer": "https://zitadel.example.com/oauth2",
    "AuthKeysLocation": "https://zitadel.example.com/oauth2/keys",
    "OIDCConfigEndpoint": "https://zitadel.example.com/.well-known/openid-configuration",
    "AuthClientID": "old-client-id",
    "AuthUserIDClaim": "preferred_username"
  },
  "IdpManagerConfig": {
    "ManagerType": "zitadel",
    "ClientConfig": {
      "Issuer": "https://zitadel.example.com",
      "ClientID": "zit-id",
      "ClientSecret": "zit-secret"
    }
  }
}`
		require.NoError(t, os.WriteFile(configPath, []byte(originalConfig), 0600))

		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain: "mgmt.example.com",
			},
		}
		conn := &dex.Connector{
			Type: "zitadel",
			Name: "zitadel",
			ID:   "zitadel",
			Config: map[string]interface{}{
				"issuer":       "https://zitadel.example.com",
				"clientID":     "zit-id",
				"clientSecret": "zit-secret",
			},
		}

		err := generateConfig(configPath, conn, cfg, false)
		require.NoError(t, err)

		// Check backup was created
		backupPath := configPath + ".bak"
		backupData, err := os.ReadFile(backupPath)
		require.NoError(t, err)
		assert.Equal(t, originalConfig, string(backupData))

		// Read and parse the new config
		newData, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(newData, &result))

		// IdpManagerConfig should be removed
		_, hasOldIdp := result["IdpManagerConfig"]
		assert.False(t, hasOldIdp, "IdpManagerConfig should be removed")

		// EmbeddedIdP should be present
		embeddedIdP, ok := result["EmbeddedIdP"].(map[string]interface{})
		require.True(t, ok, "EmbeddedIdP should be present")
		assert.Equal(t, true, embeddedIdP["Enabled"])
		assert.Equal(t, "https://mgmt.example.com/oauth2", embeddedIdP["Issuer"])
		assert.Equal(t, true, embeddedIdP["LocalAuthDisabled"])
		assert.Equal(t, true, embeddedIdP["SignKeyRefreshEnabled"])

		// HttpConfig should be updated
		httpConfig, ok := result["HttpConfig"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "https://mgmt.example.com/oauth2", httpConfig["AuthIssuer"])
		assert.Equal(t, "https://mgmt.example.com/oauth2/keys", httpConfig["AuthKeysLocation"])
		assert.Equal(t, "https://mgmt.example.com/oauth2/.well-known/openid-configuration", httpConfig["OIDCConfigEndpoint"])
		assert.Equal(t, "netbird-dashboard", httpConfig["AuthClientID"])
		// AuthUserIDClaim should be preserved since it was already set
		assert.Equal(t, "preferred_username", httpConfig["AuthUserIDClaim"])

		// Datadir should be preserved
		assert.Equal(t, "/var/lib/netbird", result["Datadir"])
	})

	t.Run("sets AuthUserIDClaim when not present", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		originalConfig := `{
  "HttpConfig": {
    "LetsEncryptDomain": "mgmt.example.com"
  }
}`
		require.NoError(t, os.WriteFile(configPath, []byte(originalConfig), 0600))

		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain: "mgmt.example.com",
			},
		}
		conn := &dex.Connector{Type: "oidc", Name: "test", ID: "test"}

		err := generateConfig(configPath, conn, cfg, false)
		require.NoError(t, err)

		newData, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(newData, &result))

		httpConfig := result["HttpConfig"].(map[string]interface{})
		assert.Equal(t, "sub", httpConfig["AuthUserIDClaim"])
	})

	t.Run("dry run does not write files", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		originalConfig := `{"HttpConfig": {"LetsEncryptDomain": "mgmt.example.com"}}`
		require.NoError(t, os.WriteFile(configPath, []byte(originalConfig), 0600))

		cfg := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain: "mgmt.example.com",
			},
		}
		conn := &dex.Connector{Type: "oidc", Name: "test", ID: "test"}

		err := generateConfig(configPath, conn, cfg, true)
		require.NoError(t, err)

		// Original should be unchanged
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Equal(t, originalConfig, string(data))

		// No backup should exist
		_, err = os.Stat(configPath + ".bak")
		assert.True(t, os.IsNotExist(err))
	})
}
