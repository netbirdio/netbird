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
	"github.com/netbirdio/netbird/management/server/idp/migration"
)

// TestMigrationServerInterface is a compile-time check that migrationServer
// implements the migration.Server interface.
func TestMigrationServerInterface(t *testing.T) {
	var _ migration.Server = (*migrationServer)(nil)
}

func TestDecodeConnectorConfig(t *testing.T) {
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

	result, err := decodeConnectorConfig(encoded)
	require.NoError(t, err)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "oidc", result.Type)
	assert.Equal(t, "https://example.com", result.Config["issuer"])
}

func TestDecodeConnectorConfig_InvalidBase64(t *testing.T) {
	_, err := decodeConnectorConfig("not-valid-base64!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decode")
}

func TestDecodeConnectorConfig_InvalidJSON(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := decodeConnectorConfig(encoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "json unmarshal")
}

func TestDecodeConnectorConfig_EmptyConnectorID(t *testing.T) {
	conn := dex.Connector{
		Type: "oidc",
		Name: "no-id",
		ID:   "",
	}
	data, err := json.Marshal(conn)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(data)
	_, err = decodeConnectorConfig(encoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector ID is empty")
}

func TestValidateConfig(t *testing.T) {
	valid := &migrationConfig{
		configPath:  "/etc/netbird/management.json",
		dataDir:     "/var/lib/netbird",
		idpSeedInfo: "some-base64",
		apiUrl:      "https://api.example.com",
		dashboardUrl: "https://dash.example.com",
	}

	t.Run("valid config", func(t *testing.T) {
		require.NoError(t, validateConfig(valid))
	})

	t.Run("missing configPath", func(t *testing.T) {
		cfg := *valid
		cfg.configPath = ""
		err := validateConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--config")
	})

	t.Run("missing dataDir", func(t *testing.T) {
		cfg := *valid
		cfg.dataDir = ""
		err := validateConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--datadir")
	})

	t.Run("missing idpSeedInfo", func(t *testing.T) {
		cfg := *valid
		cfg.idpSeedInfo = ""
		err := validateConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--idp-seed-info")
	})

	t.Run("missing apiUrl", func(t *testing.T) {
		cfg := *valid
		cfg.apiUrl = ""
		err := validateConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--api-domain")
	})

	t.Run("missing dashboardUrl", func(t *testing.T) {
		cfg := *valid
		cfg.dashboardUrl = ""
		err := validateConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--dashboard-domain")
	})
}

func TestApplyOverrides_MostGranularWins(t *testing.T) {
	t.Run("specific flags beat --domain", func(t *testing.T) {
		cfg := &migrationConfig{
			apiUrl:       "api.specific.com",
			dashboardUrl: "dash.specific.com",
		}
		applyOverrides(cfg, "broad.com")

		assert.Equal(t, "api.specific.com", cfg.apiUrl)
		assert.Equal(t, "dash.specific.com", cfg.dashboardUrl)
	})

	t.Run("--domain fills blanks when specific flags missing", func(t *testing.T) {
		cfg := &migrationConfig{}
		applyOverrides(cfg, "broad.com")

		assert.Equal(t, "broad.com", cfg.apiUrl)
		assert.Equal(t, "broad.com", cfg.dashboardUrl)
	})

	t.Run("--domain fills only the missing specific flag", func(t *testing.T) {
		cfg := &migrationConfig{
			apiUrl: "api.specific.com",
		}
		applyOverrides(cfg, "broad.com")

		assert.Equal(t, "api.specific.com", cfg.apiUrl)
		assert.Equal(t, "broad.com", cfg.dashboardUrl)
	})

	t.Run("NETBIRD_DOMAIN overrides flags", func(t *testing.T) {
		cfg := &migrationConfig{
			apiUrl:       "api.flag.com",
			dashboardUrl: "dash.flag.com",
		}
		t.Setenv("NETBIRD_DOMAIN", "env-broad.com")

		applyOverrides(cfg, "")

		assert.Equal(t, "env-broad.com", cfg.apiUrl)
		assert.Equal(t, "env-broad.com", cfg.dashboardUrl)
	})

	t.Run("specific env vars beat NETBIRD_DOMAIN", func(t *testing.T) {
		cfg := &migrationConfig{}
		t.Setenv("NETBIRD_DOMAIN", "env-broad.com")
		t.Setenv("NETBIRD_API_URL", "api.env-specific.com")
		t.Setenv("NETBIRD_DASHBOARD_URL", "dash.env-specific.com")

		applyOverrides(cfg, "")

		assert.Equal(t, "api.env-specific.com", cfg.apiUrl)
		assert.Equal(t, "dash.env-specific.com", cfg.dashboardUrl)
	})

	t.Run("one specific env var overrides only its field", func(t *testing.T) {
		cfg := &migrationConfig{}
		t.Setenv("NETBIRD_DOMAIN", "env-broad.com")
		t.Setenv("NETBIRD_API_URL", "api.env-specific.com")

		applyOverrides(cfg, "")

		assert.Equal(t, "api.env-specific.com", cfg.apiUrl)
		assert.Equal(t, "env-broad.com", cfg.dashboardUrl)
	})

	t.Run("specific env vars beat all flags combined", func(t *testing.T) {
		cfg := &migrationConfig{
			apiUrl:       "api.flag.com",
			dashboardUrl: "dash.flag.com",
		}
		t.Setenv("NETBIRD_API_URL", "api.env.com")
		t.Setenv("NETBIRD_DASHBOARD_URL", "dash.env.com")

		applyOverrides(cfg, "domain-flag.com")

		assert.Equal(t, "api.env.com", cfg.apiUrl)
		assert.Equal(t, "dash.env.com", cfg.dashboardUrl)
	})
}

func TestBuildUrl(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		path     string
		expected string
	}{
		{"with https scheme", "https://example.com", "/oauth2", "https://example.com/oauth2"},
		{"with http scheme", "http://example.com", "/oauth2/callback", "http://example.com/oauth2/callback"},
		{"bare domain", "example.com", "/oauth2", "https://example.com/oauth2"},
		{"domain with port", "example.com:8080", "/nb-auth", "https://example.com:8080/nb-auth"},
		{"trailing slash on uri", "https://example.com/", "/oauth2", "https://example.com/oauth2"},
		{"nested path", "https://example.com", "/oauth2/callback", "https://example.com/oauth2/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildUrl(tt.uri, tt.path))
		})
	}
}

func TestGenerateConfig(t *testing.T) {
	t.Run("generates valid config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		originalConfig := `{
  "Datadir": "/var/lib/netbird",
  "HttpConfig": {
    "LetsEncryptDomain": "mgmt.example.com",
    "CertFile": "/etc/ssl/cert.pem",
    "CertKey": "/etc/ssl/key.pem",
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

		cfg := &migrationConfig{
			configPath:   configPath,
			dashboardUrl: "https://mgmt.example.com",
			apiUrl:       "https://mgmt.example.com",
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
		mgmtConfig := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain: "mgmt.example.com",
			},
		}

		err := generateConfig(cfg, conn, mgmtConfig)
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

		// PKCEAuthorizationFlow should be removed
		_, hasPKCE := result["PKCEAuthorizationFlow"]
		assert.False(t, hasPKCE, "PKCEAuthorizationFlow should be removed")

		// EmbeddedIdP should be present with minimal fields
		embeddedIdP, ok := result["EmbeddedIdP"].(map[string]interface{})
		require.True(t, ok, "EmbeddedIdP should be present")
		assert.Equal(t, true, embeddedIdP["Enabled"])
		assert.Equal(t, "https://mgmt.example.com/oauth2", embeddedIdP["Issuer"])
		assert.Nil(t, embeddedIdP["LocalAuthDisabled"], "LocalAuthDisabled should not be set")
		assert.Nil(t, embeddedIdP["SignKeyRefreshEnabled"], "SignKeyRefreshEnabled should not be set")
		assert.Nil(t, embeddedIdP["CLIRedirectURIs"], "CLIRedirectURIs should not be set")

		// Static connector's redirectURI should use the management domain
		connectors := embeddedIdP["StaticConnectors"].([]interface{})
		require.Len(t, connectors, 1)
		firstConn := connectors[0].(map[string]interface{})
		connCfg := firstConn["config"].(map[string]interface{})
		assert.Equal(t, "https://mgmt.example.com/oauth2/callback", connCfg["redirectURI"],
			"redirectURI should be overridden to use the management domain")

		// HttpConfig should only have CertFile and CertKey
		httpConfig, ok := result["HttpConfig"].(map[string]interface{})
		require.True(t, ok, "HttpConfig should be present")
		assert.Equal(t, "/etc/ssl/cert.pem", httpConfig["CertFile"])
		assert.Equal(t, "/etc/ssl/key.pem", httpConfig["CertKey"])
		assert.Nil(t, httpConfig["AuthIssuer"], "AuthIssuer should be stripped")

		// Datadir should be preserved
		assert.Equal(t, "/var/lib/netbird", result["Datadir"])
	})

	t.Run("dry run does not write files", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "management.json")

		originalConfig := `{"HttpConfig": {"CertFile": "", "CertKey": ""}}`
		require.NoError(t, os.WriteFile(configPath, []byte(originalConfig), 0600))

		cfg := &migrationConfig{
			configPath:   configPath,
			dashboardUrl: "https://mgmt.example.com",
			apiUrl:       "https://mgmt.example.com",
			dryRun:       true,
		}
		conn := &dex.Connector{Type: "oidc", Name: "test", ID: "test"}
		mgmtConfig := &nbconfig.Config{
			HttpConfig: &nbconfig.HttpServerConfig{
				LetsEncryptDomain: "mgmt.example.com",
			},
		}

		err := generateConfig(cfg, conn, mgmtConfig)
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
