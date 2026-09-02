package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

func TestLoadManagementConfigUsesDefaultDataDirForEmptyValue(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"Datadir":""}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, defaultMgmtDataDir, cfg.Datadir, "Empty legacy values should use the default data directory")
}

func TestLoadManagementConfigPreservesExtraConfigKeyCase(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "IdpManagerConfig": {
    "ExtraConfig": {
      "ServiceAccountKey": "service-account-key",
      "CustomerId": "customer-id"
    }
  }
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.IdpManagerConfig, "IDP configuration should be decoded")
	assert.Equal(t, map[string]string{
		"ServiceAccountKey": "service-account-key",
		"CustomerId":        "customer-id",
	}, map[string]string(cfg.IdpManagerConfig.ExtraConfig), "IDP-specific keys should retain their case")
}

func TestLoadManagementConfigPreservesEmptyHTTPConfig(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"HttpConfig":{}}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	assert.NotNil(t, cfg.HttpConfig, "An explicitly configured empty HTTP section should remain present")
}

func TestLoadManagementConfigPreservesJSONShapes(t *testing.T) {
	clearManagementConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *nbconfig.Config)
	}{
		{
			name:     "mixed case struct field",
			contents: `{"dAtAdIr":"/mixed-case"}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "/mixed-case", cfg.Datadir, "JSON struct fields should remain case-insensitive")
			},
		},
		{
			name:     "empty nested pointer",
			contents: `{"IdpManagerConfig":{"ClientConfig":{}}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.IdpManagerConfig, "IDP configuration should remain present")
				assert.NotNil(t, cfg.IdpManagerConfig.ClientConfig,
					"An explicitly configured empty nested pointer should remain present")
			},
		},
		{
			name:     "empty map",
			contents: `{"IdpManagerConfig":{"ExtraConfig":{}}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.IdpManagerConfig, "IDP configuration should remain present")
				assert.NotNil(t, cfg.IdpManagerConfig.ExtraConfig,
					"An explicitly configured empty map should remain non-nil")
			},
		},
		{
			name:     "empty slice",
			contents: `{"Stuns":[]}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.NotNil(t, cfg.Stuns, "An explicitly configured empty slice should remain non-nil")
				assert.Empty(t, cfg.Stuns, "An explicitly configured empty slice should remain empty")
			},
		},
		{
			name:     "empty account map",
			contents: `{"PerAccountHighestSupportedSyncMessageVersion":{}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.NotNil(t, cfg.PerAccountHighestSupportedSyncMessageVersion,
					"An explicitly configured empty account map should remain non-nil")
			},
		},
		{
			name:     "null pointer",
			contents: `{"HttpConfig":null}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.HttpConfig, "A null pointer should remain nil")
			},
		},
		{
			name:     "unknown field",
			contents: `{"Datadir":"/known-data","UnknownSetting":true}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "/known-data", cfg.Datadir, "Unknown JSON fields should remain ignored")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadAdminMgmtConfigPreservesLegacyEmptyDataDir(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{}`), 0o600))

	oldConfigPath := nbconfig.MgmtConfigPath
	oldAdminDatadir := adminDatadir
	nbconfig.MgmtConfigPath = configPath
	adminDatadir = ""
	t.Cleanup(func() {
		nbconfig.MgmtConfigPath = oldConfigPath
		adminDatadir = oldAdminDatadir
	})

	cfg, datadir, err := loadAdminMgmtConfig(context.Background(), false)
	require.NoError(t, err)
	assert.Empty(t, cfg.Datadir, "Admin commands should retain the legacy empty data directory")
	assert.Empty(t, datadir, "Admin commands should retain the legacy empty effective data directory")
}

func TestEnsureEncryptionKeyDoesNotPersistUnreferencedEnvironmentSecrets(t *testing.T) {
	const environmentSecret = "environment-client-secret"

	clearManagementConfigEnvironment(t)
	t.Setenv("NB_IDPMANAGERCONFIG_CLIENTCONFIG_CLIENTSECRET", environmentSecret)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "IdpManagerConfig": {
    "ClientConfig": {}
  }
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NoError(t, EnsureEncryptionKey(context.Background(), configPath, cfg))

	persistedConfig, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(persistedConfig, []byte(environmentSecret)),
		"An environment value absent from the file should not be persisted")
}

func TestEnsureEncryptionKeyPreservesTemplateExpandedValues(t *testing.T) {
	const templateSecret = "template-client-secret"

	clearManagementConfigEnvironment(t)
	t.Setenv("MANAGEMENT_TEMPLATE_SECRET", templateSecret)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "IdpManagerConfig": {
    "ClientConfig": {
      "ClientSecret": "{{ .MANAGEMENT_TEMPLATE_SECRET }}"
    }
  }
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NoError(t, EnsureEncryptionKey(context.Background(), configPath, cfg))

	persistedConfig, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(persistedConfig, []byte(templateSecret)),
		"Template-expanded values were historically persisted during key generation")
}

func TestLoadMgmtConfigPreservesLegacyDataDirPrecedence(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "Datadir": "/stale-config-directory",
  "DataStoreEncryptionKey": "configured-key",
  "HttpConfig": {
    "AuthAudience": "test-audience"
  }
}`), 0o600))

	cfg, err := LoadMgmtConfig(context.Background(), configPath, unchangedManagementFlags())
	require.NoError(t, err)
	assert.Equal(t, defaultMgmtDataDir, cfg.Datadir,
		"The historical command default should continue to override a stale config value")
}

func TestApplyCommandLineOverridesPreservesLegacyEmptyValues(t *testing.T) {
	oldDatadir := mgmtDataDir
	oldLetsencryptDomain := mgmtLetsencryptDomain
	oldCertFile := certFile
	oldCertKey := certKey
	t.Cleanup(func() {
		mgmtDataDir = oldDatadir
		mgmtLetsencryptDomain = oldLetsencryptDomain
		certFile = oldCertFile
		certKey = oldCertKey
	})

	tests := []struct {
		name      string
		configure func(*testing.T, *pflag.FlagSet)
		validate  func(*testing.T, *nbconfig.Config)
	}{
		{
			name: "empty datadir",
			configure: func(t *testing.T, flags *pflag.FlagSet) {
				mgmtDataDir = ""
				require.NoError(t, flags.Set("datadir", ""))
			},
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "/file-data", cfg.Datadir, "An empty datadir flag should not clear the file value")
			},
		},
		{
			name: "empty letsencrypt domain",
			configure: func(t *testing.T, flags *pflag.FlagSet) {
				mgmtLetsencryptDomain = ""
				require.NoError(t, flags.Set("letsencrypt-domain", ""))
			},
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "file.example.com", cfg.HttpConfig.LetsEncryptDomain,
					"An empty letsencrypt flag should not clear the file value")
			},
		},
		{
			name: "empty certificate pair",
			configure: func(t *testing.T, flags *pflag.FlagSet) {
				certFile = ""
				certKey = ""
				require.NoError(t, flags.Set("cert-file", ""))
				require.NoError(t, flags.Set("cert-key", ""))
			},
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "/file/tls.crt", cfg.HttpConfig.CertFile,
					"An empty certificate pair should not clear the file certificate")
				assert.Equal(t, "/file/tls.key", cfg.HttpConfig.CertKey,
					"An empty certificate pair should not clear the file key")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mgmtDataDir = defaultMgmtDataDir
			mgmtLetsencryptDomain = ""
			certFile = ""
			certKey = ""
			flags := unchangedManagementFlags()
			test.configure(t, flags)
			cfg := &nbconfig.Config{
				Datadir: "/file-data",
				HttpConfig: &nbconfig.HttpServerConfig{
					LetsEncryptDomain: "file.example.com",
					CertFile:          "/file/tls.crt",
					CertKey:           "/file/tls.key",
				},
			}

			ApplyCommandLineOverrides(cfg, flags)
			test.validate(t, cfg)
		})
	}
}

func TestManagementPortDefaultsRemainCompatible(t *testing.T) {
	tests := []struct {
		name       string
		httpConfig string
		flags      map[string]string
		expected   int
	}{
		{
			name:       "no TLS",
			httpConfig: `{"AuthAudience":"test-audience"}`,
			expected:   80,
		},
		{
			name:       "file-only letsencrypt",
			httpConfig: `{"AuthAudience":"test-audience","LetsEncryptDomain":"management.example.com"}`,
			expected:   80,
		},
		{
			name:       "file certificate pair",
			httpConfig: `{"AuthAudience":"test-audience","CertFile":"/tls.crt","CertKey":"/tls.key"}`,
			expected:   443,
		},
		{
			name:       "letsencrypt flag",
			httpConfig: `{"AuthAudience":"test-audience"}`,
			flags:      map[string]string{"letsencrypt-domain": "management.example.com"},
			expected:   443,
		},
		{
			name:       "explicit zero port",
			httpConfig: `{"AuthAudience":"test-audience"}`,
			flags:      map[string]string{"port": "0"},
			expected:   0,
		},
		{
			name:       "explicit nonzero port",
			httpConfig: `{"AuthAudience":"test-audience"}`,
			flags:      map[string]string{"port": "10002"},
			expected:   10002,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := runManagementPreRun(t, test.httpConfig, test.flags)
			assert.Equal(t, test.expected, actual, "Management implicit port selection should retain legacy behavior")
		})
	}
}

func TestLegacyManagementFlagsRemainRegistered(t *testing.T) {
	for _, name := range []string{
		"port",
		"disable-legacy-port",
		"metrics-port",
		"datadir",
		"config",
		"letsencrypt-domain",
		"single-account-mode-domain",
		"disable-single-account-mode",
		"cert-file",
		"cert-key",
		"disable-anonymous-metrics",
		"dns-domain",
		idpSignKeyRefreshEnabledFlagName,
		"user-delete-from-idp",
		"disable-geolite-update",
	} {
		assert.NotNil(t, mgmtCmd.Flags().Lookup(name), "Legacy Management flag %s should remain registered", name)
	}
	for _, name := range []string{"log-level", "log-file"} {
		assert.NotNil(t, rootCmd.PersistentFlags().Lookup(name),
			"Legacy persistent Management flag %s should remain registered", name)
	}
}

// management-01: environment variables were never read directly by the legacy loader.
func TestLoadManagementConfigPreservesLegacyFileValuesOverEnvironment(t *testing.T) {
	const templateAudience = "template-audience"

	clearManagementConfigEnvironment(t)
	t.Setenv("MANAGEMENT_TEMPLATE_AUDIENCE", templateAudience)

	tests := []struct {
		name        string
		environment map[string]string
		contents    string
		validate    func(*testing.T, *nbconfig.Config)
	}{
		{
			name:        "http audience",
			environment: map[string]string{"NB_HTTPCONFIG_AUTHAUDIENCE": "env-aud"},
			contents:    `{"HttpConfig":{"AuthAudience":"file-aud"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.Equal(t, "file-aud", cfg.HttpConfig.AuthAudience,
					"The legacy loader never read NB_ environment variables; the file value must win")
			},
		},
		{
			name:        "relay secret",
			environment: map[string]string{"NB_RELAY_SECRET": "env-secret"},
			contents:    `{"Relay":{"Addresses":["rel://a"],"Secret":"file-secret"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "Relay configuration should be decoded")
				assert.Equal(t, "file-secret", cfg.Relay.Secret,
					"The legacy loader never read NB_ environment variables; the file value must win")
			},
		},
		{
			name:        "turn secret",
			environment: map[string]string{"NB_TURNCONFIG_SECRET": "env-secret"},
			contents:    `{"TURNConfig":{"Secret":"file-secret"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.TURNConfig, "TURN configuration should be decoded")
				assert.Equal(t, "file-secret", cfg.TURNConfig.Secret,
					"The legacy loader never read NB_ environment variables; the file value must win")
			},
		},
		{
			name:        "idp client secret",
			environment: map[string]string{"NB_IDPMANAGERCONFIG_CLIENTCONFIG_CLIENTSECRET": "env-secret"},
			contents:    `{"IdpManagerConfig":{"ClientConfig":{"ClientSecret":"file-secret"}}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.IdpManagerConfig, "IDP configuration should be decoded")
				require.NotNil(t, cfg.IdpManagerConfig.ClientConfig, "IDP client configuration should be decoded")
				assert.Equal(t, "file-secret", cfg.IdpManagerConfig.ClientConfig.ClientSecret,
					"The legacy loader never read NB_ environment variables; the file value must win")
			},
		},
		{
			name:        "sign key refresh",
			environment: map[string]string{"NB_HTTPCONFIG_IDPSIGNKEYREFRESHENABLED": "true"},
			contents:    `{"HttpConfig":{"IdpSignKeyRefreshEnabled":false}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.False(t, cfg.HttpConfig.IdpSignKeyRefreshEnabled,
					"Only the --idp-sign-key-refresh-enabled flag could toggle the refresh setting outside the file")
			},
		},
		{
			name:        "embedded idp storage dsn",
			environment: map[string]string{"NB_EMBEDDEDIDP_STORAGE_CONFIG_DSN": "env-dsn"},
			contents:    `{"EmbeddedIdP":{"Enabled":true,"Storage":{"Type":"postgres","Config":{"DSN":"file-dsn"}}}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.EmbeddedIdP, "Embedded IdP configuration should be decoded")
				assert.Equal(t, "file-dsn", cfg.EmbeddedIdP.Storage.Config.DSN,
					"The legacy loader never read NB_ environment variables; the file value must win")
			},
		},
		{
			name:        "template expanded value",
			environment: map[string]string{"NB_HTTPCONFIG_AUTHAUDIENCE": "env-aud"},
			contents:    `{"HttpConfig":{"AuthAudience":"{{ .MANAGEMENT_TEMPLATE_AUDIENCE }}"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.Equal(t, templateAudience, cfg.HttpConfig.AuthAudience,
					"Template references were the only supported environment input and must win over NB_ variables")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-02 / management-03: the encryption key came only from the file and the file
// was only rewritten when it contained no key at all.
func TestLoadManagementConfigPreservesLegacyFileEncryptionKey(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name           string
		environmentKey string
	}{
		{name: "empty environment key", environmentKey: ""},
		{name: "different environment key", environmentKey: "environment-key"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NB_DATASTOREENCRYPTIONKEY", test.environmentKey)
			configPath := filepath.Join(t.TempDir(), "management.json")
			contents := []byte(`{"DataStoreEncryptionKey":"operator-key","HttpConfig":{"AuthAudience":"file-aud"}}`)
			require.NoError(t, os.WriteFile(configPath, contents, 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, "operator-key", cfg.DataStoreEncryptionKey,
				"NB_DATASTOREENCRYPTIONKEY was never read; the file key must be used")

			require.NoError(t, EnsureEncryptionKey(context.Background(), configPath, cfg))
			assert.Equal(t, "operator-key", cfg.DataStoreEncryptionKey,
				"EnsureEncryptionKey must not replace an operator-provided key")
			persistedConfig, err := os.ReadFile(configPath)
			require.NoError(t, err)
			assert.Equal(t, string(contents), string(persistedConfig),
				"The config file must not be rewritten when it already contains an encryption key")
		})
	}
}

// management-04 / management-05: implicit TLS port selection only considered the
// --letsencrypt-domain flag and the certificate pair from the file.
func TestManagementPortDefaultsIgnoreEnvironmentTLS(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		expected    int
	}{
		{
			name:        "letsencrypt domain from environment",
			environment: map[string]string{"NB_HTTPCONFIG_LETSENCRYPTDOMAIN": "management.example.com"},
			expected:    80,
		},
		{
			name: "certificate pair from environment",
			environment: map[string]string{
				"NB_HTTPCONFIG_CERTFILE": "/tls.crt",
				"NB_HTTPCONFIG_CERTKEY":  "/tls.key",
			},
			expected: 80,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := runManagementPreRunWithEnvironment(t, `{"AuthAudience":"test-audience"}`, nil, test.environment)
			assert.Equal(t, test.expected, actual,
				"Environment variables never enabled TLS, so the implicit port must remain the plain HTTP default")
		})
	}
}

// management-06: an empty-but-set environment variable was ignored and never cleared file values.
func TestLoadManagementConfigPreservesLegacyFileValuesOverEmptyEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		contents        string
		validate        func(*testing.T, *nbconfig.Config)
	}{
		{
			name:            "http audience",
			environmentName: "NB_HTTPCONFIG_AUTHAUDIENCE",
			contents:        `{"HttpConfig":{"AuthAudience":"file-aud"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.Equal(t, "file-aud", cfg.HttpConfig.AuthAudience,
					"An empty NB_ variable was ignored and must not clear the file value")
			},
		},
		{
			name:            "relay addresses",
			environmentName: "NB_RELAY_ADDRESSES",
			contents:        `{"Relay":{"Addresses":["rel://a"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "Relay configuration should be decoded")
				assert.Equal(t, []string{"rel://a"}, cfg.Relay.Addresses,
					"An empty NB_ variable was ignored and must not empty the relay list")
			},
		},
		{
			name:            "stuns",
			environmentName: "NB_STUNS",
			contents:        `{"Stuns":[{"Proto":"udp","URI":"stun:stun.example.com:3478"}]}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Len(t, cfg.Stuns, 1, "An empty NB_ variable was ignored and must not empty the STUN list")
			},
		},
		{
			name:            "trusted proxies",
			environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIES",
			contents:        `{"ReverseProxy":{"TrustedHTTPProxies":["10.0.0.0/8"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Len(t, cfg.ReverseProxy.TrustedHTTPProxies, 1,
					"An empty NB_ variable was ignored and must not empty the trusted proxy list")
			},
		},
		{
			name:            "datadir",
			environmentName: "NB_DATADIR",
			contents:        `{"Datadir":"/file-data"}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "/file-data", cfg.Datadir,
					"An empty NB_ variable was ignored and must not discard the file data directory")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, "")
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-07: NB_DATADIR had no effect on either the server or the admin commands.
func TestLoadMgmtConfigIgnoresEnvironmentDataDir(t *testing.T) {
	clearManagementConfigEnvironment(t)
	t.Setenv("NB_DATADIR", "/env-data")

	oldDatadir := mgmtDataDir
	mgmtDataDir = defaultMgmtDataDir
	t.Cleanup(func() { mgmtDataDir = oldDatadir })

	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "DataStoreEncryptionKey": "configured-key",
  "HttpConfig": {
    "AuthAudience": "test-audience"
  }
}`), 0o600))

	cfg, err := LoadMgmtConfig(context.Background(), configPath, unchangedManagementFlags())
	require.NoError(t, err)
	assert.Equal(t, defaultMgmtDataDir, cfg.Datadir,
		"The server data directory came from the --datadir flag default; NB_DATADIR was never read")
}

func TestLoadAdminMgmtConfigIgnoresEnvironmentDataDir(t *testing.T) {
	clearManagementConfigEnvironment(t)
	t.Setenv("NB_DATADIR", "/env-data")
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"Datadir":"/file-data"}`), 0o600))
	setAdminConfigPath(t, configPath)

	cfg, datadir, err := loadAdminMgmtConfig(context.Background(), false)
	require.NoError(t, err)
	assert.Equal(t, "/file-data", cfg.Datadir, "Admin commands read the data directory from the file only")
	assert.Equal(t, "/file-data", datadir, "Admin commands read the effective data directory from the file only")
}

// management-08: unparsable environment values were ignored instead of aborting startup.
func TestLoadManagementConfigIgnoresInvalidScalarEnvironmentValues(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
	}{
		{name: "invalid bool", environmentName: "NB_DISABLEDEFAULTPOLICY", value: "maybe"},
		{name: "padded bool", environmentName: "NB_DISABLEDEFAULTPOLICY", value: " true"},
		{name: "invalid int", environmentName: "NB_HIGHESTSUPPORTEDSYNCMESSAGEVERSION", value: "abc"},
		{name: "float int", environmentName: "NB_HIGHESTSUPPORTEDSYNCMESSAGEVERSION", value: "1.0"},
		{name: "negative uint", environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT", value: "-1"},
		{name: "empty duration", environmentName: "NB_TURNCONFIG_CREDENTIALSTTL", value: ""},
		{name: "invalid duration", environmentName: "NB_TURNCONFIG_CREDENTIALSTTL", value: "abc"},
		{name: "numeric duration", environmentName: "NB_TURNCONFIG_CREDENTIALSTTL", value: "3600000000000"},
		{name: "invalid prefix", environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIES", value: "bad"},
		{name: "address instead of prefix", environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIES", value: "10.0.0.1"},
		{name: "overflowing login flag", environmentName: "NB_PKCEAUTHORIZATIONFLOW_PROVIDERCONFIG_LOGINFLAG", value: "300"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(`{
  "Datadir": "/file-data",
  "TURNConfig": {"CredentialsTTL": "1h"},
  "PKCEAuthorizationFlow": {"ProviderConfig": {"LoginFlag": 1}}
}`), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err, "Environment variables were never read, so an unparsable value must not fail startup")
			assert.Equal(t, "/file-data", cfg.Datadir, "File values should be used when the environment is ignored")
		})
	}
}

// management-09: a variable named after a configuration section had no effect.
func TestLoadManagementConfigIgnoresSectionEnvironmentVariables(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
		contents        string
		validate        func(*testing.T, *nbconfig.Config)
	}{
		{
			name:            "http config",
			environmentName: "NB_HTTPCONFIG",
			value:           "x",
			contents:        `{"HttpConfig":{"AuthAudience":"file-aud"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "A section-named variable was ignored and must not drop the HTTP section")
				assert.Equal(t, "file-aud", cfg.HttpConfig.AuthAudience, "The HTTP section should be loaded from the file")
			},
		},
		{
			name:            "relay",
			environmentName: "NB_RELAY",
			value:           "x",
			contents:        `{"Relay":{"Addresses":["rel://a"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "A section-named variable was ignored and must not drop the relay section")
				assert.Equal(t, []string{"rel://a"}, cfg.Relay.Addresses, "The relay section should be loaded from the file")
			},
		},
		{
			name:            "empty idp manager config",
			environmentName: "NB_IDPMANAGERCONFIG",
			value:           "",
			contents:        `{"IdpManagerConfig":{"ManagerType":"none"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.IdpManagerConfig, "A section-named variable was ignored and must not drop the IDP section")
				assert.Equal(t, "none", cfg.IdpManagerConfig.ManagerType, "The IDP section should be loaded from the file")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-10: the optional embedded IdP section existed only when present in the file.
func TestLoadManagementConfigDoesNotMaterializeEmbeddedIdPFromEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
	}{
		{name: "enabled", environmentName: "NB_EMBEDDEDIDP_ENABLED", value: "true"},
		{name: "empty issuer", environmentName: "NB_EMBEDDEDIDP_ISSUER", value: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(`{"HttpConfig":{"AuthAudience":"file-aud"}}`), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			assert.Nil(t, cfg.EmbeddedIdP,
				"Without an EmbeddedIdP object in the file the section stayed nil; environment variables were never read")
		})
	}
}

// management-11: optional pointer sections stayed nil unless present in the file.
func TestLoadManagementConfigDoesNotMaterializePointersFromEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
		contents        string
		validate        func(*testing.T, *nbconfig.Config)
	}{
		{
			name:            "missing http config",
			environmentName: "NB_HTTPCONFIG_AUTHAUDIENCE",
			value:           "env-aud",
			contents:        `{}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.HttpConfig, "A missing HTTP section stayed nil; environment variables were never read")
			},
		},
		{
			name:            "null http config",
			environmentName: "NB_HTTPCONFIG_AUTHAUDIENCE",
			value:           "",
			contents:        `{"HttpConfig":null}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.HttpConfig, "A null HTTP section stayed nil; environment variables were never read")
			},
		},
		{
			name:            "signal",
			environmentName: "NB_SIGNAL_URI",
			value:           "sig:x",
			contents:        `{}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.Signal, "A missing signal section stayed nil; environment variables were never read")
			},
		},
		{
			name:            "relay",
			environmentName: "NB_RELAY_SECRET",
			value:           "s",
			contents:        `{}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.Relay, "A missing relay section stayed nil; environment variables were never read")
			},
		},
		{
			name:            "embedded idp owner",
			environmentName: "NB_EMBEDDEDIDP_OWNER_EMAIL",
			value:           "owner@example.com",
			contents:        `{"EmbeddedIdP":{"Enabled":true,"Issuer":"https://management.example.com/oauth2"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.EmbeddedIdP, "Embedded IdP configuration should be decoded")
				assert.Nil(t, cfg.EmbeddedIdP.Owner, "A missing owner stayed nil; environment variables were never read")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-12: variables named after struct slices or maps were ignored instead of aborting startup.
func TestLoadManagementConfigIgnoresCollectionEnvironmentValues(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
	}{
		{name: "stuns", environmentName: "NB_STUNS", value: "stun:stun.example.com:3478"},
		{name: "stuns json", environmentName: "NB_STUNS", value: `[{"Proto":"udp","URI":"stun:x"}]`},
		{name: "turns", environmentName: "NB_TURNCONFIG_TURNS", value: "turn:x"},
		{name: "static connectors", environmentName: "NB_EMBEDDEDIDP_STATICCONNECTORS", value: "x"},
		{name: "empty per account versions", environmentName: "NB_PERACCOUNTHIGHESTSUPPORTEDSYNCMESSAGEVERSION", value: ""},
		{name: "per account versions", environmentName: "NB_PERACCOUNTHIGHESTSUPPORTEDSYNCMESSAGEVERSION", value: "acc1=1"},
		{name: "empty extra config", environmentName: "NB_IDPMANAGERCONFIG_EXTRACONFIG", value: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(`{
  "Stuns": [{"Proto":"udp","URI":"stun:file.example.com:3478"}],
  "TURNConfig": {"Turns": [{"Proto":"udp","URI":"turn:file.example.com:3478"}]},
  "EmbeddedIdP": {"Enabled": true, "Issuer": "https://management.example.com/oauth2"},
  "PerAccountHighestSupportedSyncMessageVersion": {"acc1": 1},
  "IdpManagerConfig": {"ExtraConfig": {"CustomerId": "customer-id"}}
}`), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err, "Environment variables were never read, so a collection-named variable must not fail startup")
			assert.Len(t, cfg.Stuns, 1, "File STUN servers should be retained")
			require.NotNil(t, cfg.TURNConfig, "TURN configuration should be decoded")
			assert.Len(t, cfg.TURNConfig.Turns, 1, "File TURN servers should be retained")
			assert.Equal(t, map[string]int{"acc1": 1}, cfg.PerAccountHighestSupportedSyncMessageVersion,
				"File per-account versions should be retained")
			require.NotNil(t, cfg.IdpManagerConfig, "IDP configuration should be decoded")
			assert.Equal(t, map[string]string{"CustomerId": "customer-id"}, map[string]string(cfg.IdpManagerConfig.ExtraConfig),
				"File extra IDP configuration should be retained")
		})
	}
}

// management-13: list-valued environment variables did not exist; lists came only from JSON arrays.
func TestLoadManagementConfigPreservesLegacyFileListsOverEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		value           string
		contents        string
		validate        func(*testing.T, *nbconfig.Config)
	}{
		{
			name:            "relay addresses with spaces",
			environmentName: "NB_RELAY_ADDRESSES",
			value:           "rel://a, rel://b",
			contents:        `{"Relay":{"Addresses":["rel://file"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "Relay configuration should be decoded")
				assert.Equal(t, []string{"rel://file"}, cfg.Relay.Addresses,
					"Relay addresses came only from the JSON array; environment lists were never parsed")
			},
		},
		{
			name:            "relay addresses trailing comma",
			environmentName: "NB_RELAY_ADDRESSES",
			value:           "rel://a,rel://b,",
			contents:        `{"Relay":{"Addresses":["rel://file"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "Relay configuration should be decoded")
				assert.Equal(t, []string{"rel://file"}, cfg.Relay.Addresses,
					"Relay addresses came only from the JSON array; environment lists were never parsed")
			},
		},
		{
			name:            "relay addresses json",
			environmentName: "NB_RELAY_ADDRESSES",
			value:           `["rel://a","rel://b"]`,
			contents:        `{"Relay":{"Addresses":["rel://file"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Relay, "Relay configuration should be decoded")
				assert.Equal(t, []string{"rel://file"}, cfg.Relay.Addresses,
					"Relay addresses came only from the JSON array; environment lists were never parsed")
			},
		},
		{
			name:            "grant types",
			environmentName: "NB_EMBEDDEDIDP_GRANTTYPES",
			value:           "authorization_code,refresh_token",
			contents:        `{"EmbeddedIdP":{"Enabled":true,"GrantTypes":["device_code"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.EmbeddedIdP, "Embedded IdP configuration should be decoded")
				assert.Equal(t, []string{"device_code"}, cfg.EmbeddedIdP.GrantTypes,
					"Grant types came only from the JSON array; environment lists were never parsed")
			},
		},
		{
			name:            "trusted proxies with spaces",
			environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIES",
			value:           "10.0.0.0/8, 192.168.0.0/16",
			contents:        `{"ReverseProxy":{"TrustedHTTPProxies":["172.16.0.0/12"]}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.Len(t, cfg.ReverseProxy.TrustedHTTPProxies, 1,
					"Trusted proxies came only from the JSON array; environment lists were never parsed")
				assert.Equal(t, "172.16.0.0/12", cfg.ReverseProxy.TrustedHTTPProxies[0].String(),
					"Trusted proxies came only from the JSON array; environment lists were never parsed")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err, "Environment lists were never parsed, so they must not fail startup")
			test.validate(t, cfg)
		})
	}
}

// management-14: boolean spellings in the environment were never interpreted.
func TestLoadManagementConfigIgnoresBooleanEnvironmentSpellings(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		value    string
		contents string
		expected bool
	}{
		{name: "one", value: "1", contents: `{"DisableDefaultPolicy":false}`, expected: false},
		{name: "true", value: "TRUE", contents: `{"DisableDefaultPolicy":false}`, expected: false},
		{name: "yes", value: "yes", contents: `{"DisableDefaultPolicy":false}`, expected: false},
		{name: "on", value: "on", contents: `{"DisableDefaultPolicy":false}`, expected: false},
		{name: "zero", value: "0", contents: `{"DisableDefaultPolicy":true}`, expected: true},
		{name: "no", value: "no", contents: `{"DisableDefaultPolicy":true}`, expected: true},
		{name: "off", value: "off", contents: `{"DisableDefaultPolicy":true}`, expected: true},
		{name: "empty", value: "", contents: `{"DisableDefaultPolicy":true}`, expected: true},
		{name: "invalid", value: "maybe", contents: `{"DisableDefaultPolicy":true}`, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NB_DISABLEDEFAULTPOLICY", test.value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err, "Boolean environment spellings were never interpreted, so they must not fail startup")
			assert.Equal(t, test.expected, cfg.DisableDefaultPolicy,
				"NB_DISABLEDEFAULTPOLICY was never read; the file value must be used")
		})
	}
}

// management-15: an empty environment value never zeroed numeric fields.
func TestLoadManagementConfigPreservesLegacyNumericFileValuesOverEmptyEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name            string
		environmentName string
		contents        string
		validate        func(*testing.T, *nbconfig.Config)
	}{
		{
			name:            "missing sync version",
			environmentName: "NB_HIGHESTSUPPORTEDSYNCMESSAGEVERSION",
			contents:        `{}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.HighestSupportedSyncMessageVersion,
					"An empty NB_ variable was ignored, so a missing sync version must stay nil")
			},
		},
		{
			name:            "configured sync version",
			environmentName: "NB_HIGHESTSUPPORTEDSYNCMESSAGEVERSION",
			contents:        `{"HighestSupportedSyncMessageVersion":1}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HighestSupportedSyncMessageVersion, "Sync version should be decoded")
				assert.Equal(t, 1, *cfg.HighestSupportedSyncMessageVersion,
					"An empty NB_ variable was ignored, so the file sync version must be retained")
			},
		},
		{
			name:            "trusted proxies count",
			environmentName: "NB_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT",
			contents:        `{"ReverseProxy":{"TrustedHTTPProxiesCount":2}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, uint(2), cfg.ReverseProxy.TrustedHTTPProxiesCount,
					"An empty NB_ variable was ignored, so the file proxy count must be retained")
			},
		},
		{
			name:            "access log retention",
			environmentName: "NB_REVERSEPROXY_ACCESSLOGRETENTIONDAYS",
			contents:        `{"ReverseProxy":{"AccessLogRetentionDays":30}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, 30, cfg.ReverseProxy.AccessLogRetentionDays,
					"An empty NB_ variable was ignored, so the file retention must be retained")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.environmentName, "")
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-16: admin and legacy token commands operated strictly on the file's view of the deployment.
func TestLoadAdminMgmtConfigIgnoresEnvironment(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name             string
		environment      map[string]string
		contents         string
		applyIDPDefaults bool
		validate         func(*testing.T, *nbconfig.Config)
	}{
		{
			name:        "store engine",
			environment: map[string]string{"NB_STORECONFIG_ENGINE": "postgres"},
			contents:    `{"StoreConfig":{"Engine":"sqlite"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "sqlite", string(cfg.StoreConfig.Engine),
					"Admin commands read the store engine from the file only")
			},
		},
		{
			name:        "encryption key",
			environment: map[string]string{"NB_DATASTOREENCRYPTIONKEY": "env-key"},
			contents:    `{"DataStoreEncryptionKey":"file-key"}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Equal(t, "file-key", cfg.DataStoreEncryptionKey,
					"Admin commands read the encryption key from the file only")
			},
		},
		{
			name:             "embedded idp enabled",
			environment:      map[string]string{"NB_EMBEDDEDIDP_ENABLED": "true"},
			contents:         `{"HttpConfig":{"AuthAudience":"file-aud"}}`,
			applyIDPDefaults: true,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.Nil(t, cfg.EmbeddedIdP, "Admin commands never enabled the embedded IdP from the environment")
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.Equal(t, "file-aud", cfg.HttpConfig.AuthAudience,
					"HTTP configuration must not be rewritten by an environment-enabled embedded IdP")
			},
		},
		{
			name:        "invalid value",
			environment: map[string]string{"NB_DISABLEDEFAULTPOLICY": "maybe"},
			contents:    `{"DisableDefaultPolicy":true}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				assert.True(t, cfg.DisableDefaultPolicy, "Admin commands read the policy flag from the file only")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))
			setAdminConfigPath(t, configPath)

			cfg, _, err := loadAdminMgmtConfig(context.Background(), test.applyIDPDefaults)
			require.NoError(t, err, "Admin commands never read the environment, so it must not fail loading")
			test.validate(t, cfg)
		})
	}
}

// management-17: the store engine in the config came from the file only; NETBIRD_STORE_ENGINE
// was consulted later by the store package.
func TestLoadManagementConfigIgnoresEnvironmentStoreEngine(t *testing.T) {
	clearManagementConfigEnvironment(t)
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")

	for _, value := range []string{"postgres", "Postgres"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("NB_STORECONFIG_ENGINE", value)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(`{"StoreConfig":{"Engine":""}}`), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			assert.Empty(t, string(cfg.StoreConfig.Engine),
				"NB_STORECONFIG_ENGINE was never read; an empty file engine left NETBIRD_STORE_ENGINE in charge")
		})
	}
}

// management-20: the certificate override only fired when both flag values were non-empty.
func TestApplyCommandLineOverridesPreservesLegacyMixedCertificatePair(t *testing.T) {
	oldCertFile := certFile
	oldCertKey := certKey
	t.Cleanup(func() {
		certFile = oldCertFile
		certKey = oldCertKey
	})

	tests := []struct {
		name     string
		certFile string
		certKey  string
	}{
		{name: "empty key", certFile: "/new.crt", certKey: ""},
		{name: "empty file", certFile: "", certKey: "/new.key"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certFile = test.certFile
			certKey = test.certKey
			flags := unchangedManagementFlags()
			require.NoError(t, flags.Set("cert-file", test.certFile))
			require.NoError(t, flags.Set("cert-key", test.certKey))
			cfg := &nbconfig.Config{
				HttpConfig: &nbconfig.HttpServerConfig{
					CertFile: "/file/tls.crt",
					CertKey:  "/file/tls.key",
				},
			}

			ApplyCommandLineOverrides(cfg, flags)
			assert.Equal(t, "/file/tls.crt", cfg.HttpConfig.CertFile,
				"A partially empty certificate pair never overrode the file certificate")
			assert.Equal(t, "/file/tls.key", cfg.HttpConfig.CertKey,
				"A partially empty certificate pair never overrode the file key")
		})
	}
}

// management-23: the config file was always parsed as JSON regardless of its extension.
func TestLoadManagementConfigParsesJSONRegardlessOfExtension(t *testing.T) {
	clearManagementConfigEnvironment(t)

	for _, extension := range []string{".toml", ".ini", ".env", ".dotenv", ".properties", ".props", ".prop", ".hcl", ".tfvars"} {
		t.Run(extension, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management"+extension)
			require.NoError(t, os.WriteFile(configPath, []byte(`{"Datadir":"/file-data"}`), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err, "JSON content was always accepted regardless of the file extension")
			assert.Equal(t, "/file-data", cfg.Datadir, "JSON content should be decoded regardless of the file extension")
		})
	}
}

// management-24: account IDs used as map keys kept their case.
func TestLoadManagementConfigPreservesPerAccountKeyCase(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"PerAccountHighestSupportedSyncMessageVersion":{"AbC123":1}}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"AbC123": 1}, cfg.PerAccountHighestSupportedSyncMessageVersion,
		"Per-account sync version keys are account IDs and must retain their case")
}

// management-25: connector configuration keys inside slices kept their case.
func TestLoadManagementConfigPreservesStaticConnectorConfigKeyCase(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "EmbeddedIdP": {
    "Enabled": true,
    "StaticConnectors": [
      {"type": "oidc", "id": "x", "config": {"clientID": "a", "redirectURI": "b", "insecureEnableGroups": false}}
    ]
  }
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.EmbeddedIdP, "Embedded IdP configuration should be decoded")
	require.Len(t, cfg.EmbeddedIdP.StaticConnectors, 1, "Static connectors should be decoded")
	assert.Equal(t, map[string]any{
		"clientID":             "a",
		"redirectURI":          "b",
		"insecureEnableGroups": false,
	}, cfg.EmbeddedIdP.StaticConnectors[0].Config, "Dex connector option keys are case-sensitive and must retain their case")
}

// management-26: mistyped scalars in the file were rejected instead of coerced.
func TestLoadManagementConfigRejectsWeaklyTypedFileValues(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
	}{
		{name: "string sync version", contents: `{"HighestSupportedSyncMessageVersion":"1"}`},
		{name: "string per account version", contents: `{"PerAccountHighestSupportedSyncMessageVersion":{"a":"1"}}`},
		{name: "numeric datadir", contents: `{"Datadir":123}`},
		{name: "numeric engine", contents: `{"StoreConfig":{"Engine":1}}`},
		{name: "numeric proto", contents: `{"Signal":{"Proto":1}}`},
		{name: "string bool", contents: `{"DisableDefaultPolicy":"true"}`},
		{name: "upper string bool", contents: `{"DisableDefaultPolicy":"TRUE"}`},
		{name: "yes bool", contents: `{"DisableDefaultPolicy":"yes"}`},
		{name: "on bool", contents: `{"DisableDefaultPolicy":"on"}`},
		{name: "numeric bool", contents: `{"DisableDefaultPolicy":1}`},
		{name: "string login flag", contents: `{"PKCEAuthorizationFlow":{"ProviderConfig":{"LoginFlag":"1"}}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			_, err := loadManagementConfig(configPath)
			assert.Error(t, err, "encoding/json rejected mistyped scalars, so loading must fail instead of coercing the value")
		})
	}
}

// management-27: numeric edge cases were rejected or decoded exactly rather than silently mangled.
func TestLoadManagementConfigPreservesLegacyNumericDecoding(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *nbconfig.Config, error)
	}{
		{
			name:     "fractional sync version",
			contents: `{"HighestSupportedSyncMessageVersion":1.7}`,
			validate: func(t *testing.T, _ *nbconfig.Config, err error) {
				assert.Error(t, err, "encoding/json rejected a fractional number for an int field")
			},
		},
		{
			name:     "whole float sync version",
			contents: `{"HighestSupportedSyncMessageVersion":1.0}`,
			validate: func(t *testing.T, _ *nbconfig.Config, err error) {
				assert.Error(t, err, "encoding/json rejected a float literal for an int field")
			},
		},
		{
			name:     "fractional retention days",
			contents: `{"ReverseProxy":{"AccessLogRetentionDays":7.9}}`,
			validate: func(t *testing.T, _ *nbconfig.Config, err error) {
				assert.Error(t, err, "encoding/json rejected a fractional number for an int field")
			},
		},
		{
			name:     "negative proxy count",
			contents: `{"ReverseProxy":{"TrustedHTTPProxiesCount":-1}}`,
			validate: func(t *testing.T, _ *nbconfig.Config, err error) {
				assert.Error(t, err, "encoding/json rejected a negative number for a uint field")
			},
		},
		{
			name:     "overflowing login flag",
			contents: `{"PKCEAuthorizationFlow":{"ProviderConfig":{"LoginFlag":300}}}`,
			validate: func(t *testing.T, _ *nbconfig.Config, err error) {
				assert.Error(t, err, "encoding/json rejected a number overflowing a uint8 field")
			},
		},
		{
			name:     "large sync version",
			contents: `{"HighestSupportedSyncMessageVersion":9007199254740993}`,
			validate: func(t *testing.T, cfg *nbconfig.Config, err error) {
				require.NoError(t, err)
				require.NotNil(t, cfg.HighestSupportedSyncMessageVersion, "Sync version should be decoded")
				assert.Equal(t, 9007199254740993, *cfg.HighestSupportedSyncMessageVersion,
					"encoding/json decoded large integers exactly without float64 precision loss")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			test.validate(t, cfg, err)
		})
	}
}

// management-28: the rewritten config reproduced the decoded struct shape.
func TestEnsureEncryptionKeyPersistsLegacyConfigShape(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "HttpConfig": {},
  "Relay": {},
  "IdpManagerConfig": {
    "ExtraConfig": {
      "ServiceAccountKey": "service-account-key"
    }
  },
  "PerAccountHighestSupportedSyncMessageVersion": {"AbC123": 1}
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NoError(t, EnsureEncryptionKey(context.Background(), configPath, cfg))

	persistedConfig, err := os.ReadFile(configPath)
	require.NoError(t, err)
	var persisted map[string]any
	require.NoError(t, json.Unmarshal(persistedConfig, &persisted))

	_, httpConfigIsObject := persisted["HttpConfig"].(map[string]any)
	assert.True(t, httpConfigIsObject, "An explicitly configured empty HttpConfig was persisted as an object, not null")
	_, relayIsObject := persisted["Relay"].(map[string]any)
	assert.True(t, relayIsObject, "An explicitly configured empty Relay section was persisted as an object, not null")

	idpConfig, _ := persisted["IdpManagerConfig"].(map[string]any)
	extraConfig, _ := idpConfig["ExtraConfig"].(map[string]any)
	assert.Contains(t, extraConfig, "ServiceAccountKey", "Persisted IDP-specific keys retained their case")

	perAccount, _ := persisted["PerAccountHighestSupportedSyncMessageVersion"].(map[string]any)
	assert.Contains(t, perAccount, "AbC123", "Persisted per-account keys retained their case")
}

// management-29: an empty config file failed to load instead of silently producing defaults.
func TestLoadManagementConfigRejectsEmptyFile(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, nil, 0o600))

	_, err := loadManagementConfig(configPath)
	assert.Error(t, err, "json.Unmarshal rejected a zero-byte file with 'unexpected end of JSON input'")
}

// management-30: duplicate object keys differing only in case were merged into the same struct.
func TestLoadManagementConfigMergesCaseVariantDuplicateObjects(t *testing.T) {
	clearManagementConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"Signal":{"URI":"signal.example.com:10000"},"signal":{"Proto":"udp"}}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Signal, "Signal configuration should be decoded")
	assert.Equal(t, "signal.example.com:10000", cfg.Signal.URI,
		"encoding/json decoded case-variant duplicate objects into the same struct, keeping both fields")
	assert.Equal(t, nbconfig.UDP, cfg.Signal.Proto,
		"encoding/json decoded case-variant duplicate objects into the same struct, keeping both fields")
}

// management-31: a scalar string for a slice field in the file was rejected.
func TestLoadManagementConfigRejectsScalarStringsForSlices(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
	}{
		{name: "relay addresses", contents: `{"Relay":{"Addresses":"rel://a,rel://b"}}`},
		{name: "grant types", contents: `{"EmbeddedIdP":{"GrantTypes":"authorization_code"}}`},
		{name: "trusted proxies", contents: `{"ReverseProxy":{"TrustedHTTPProxies":"10.0.0.0/8,192.168.0.0/16"}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			_, err := loadManagementConfig(configPath)
			assert.Error(t, err, "encoding/json rejected a string for a slice field instead of splitting it on commas")
		})
	}
}

// management-32: a null duration in the file was rejected.
func TestLoadManagementConfigRejectsNullDurations(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
	}{
		{name: "turn credentials ttl", contents: `{"TURNConfig":{"CredentialsTTL":null}}`},
		{name: "relay credentials ttl", contents: `{"Relay":{"CredentialsTTL":null}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			_, err := loadManagementConfig(configPath)
			assert.Error(t, err, "util.Duration rejected JSON null with 'invalid duration' instead of defaulting to 0s")
		})
	}
}

// management-critic-1: duplicate same-case object keys were decoded into the same struct, merging both blocks.
func TestLoadManagementConfigMergesSameCaseDuplicateObjects(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *nbconfig.Config)
	}{
		{
			name:     "signal",
			contents: `{"Signal":{"URI":"signal.example.com:10000"},"Signal":{"Proto":"udp"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.Signal, "Signal configuration should be decoded")
				assert.Equal(t, "signal.example.com:10000", cfg.Signal.URI,
					"encoding/json decoded duplicate Signal objects into the same struct, keeping the first block's fields")
				assert.Equal(t, nbconfig.UDP, cfg.Signal.Proto,
					"encoding/json decoded duplicate Signal objects into the same struct, keeping the second block's fields")
			},
		},
		{
			name:     "http config",
			contents: `{"HttpConfig":{"AuthAudience":"a"},"HttpConfig":{"AuthIssuer":"i"}}`,
			validate: func(t *testing.T, cfg *nbconfig.Config) {
				require.NotNil(t, cfg.HttpConfig, "HTTP configuration should be decoded")
				assert.Equal(t, "a", cfg.HttpConfig.AuthAudience,
					"encoding/json decoded duplicate HttpConfig objects into the same struct, keeping the first block's fields")
				assert.Equal(t, "i", cfg.HttpConfig.AuthIssuer,
					"encoding/json decoded duplicate HttpConfig objects into the same struct, keeping the second block's fields")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// management-critic-2: case-variant duplicate scalar keys were applied in document order, so the last one won.
func TestLoadManagementConfigPreservesLegacyDocumentOrderForCaseVariantScalars(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
		expected string
	}{
		{
			name:     "uppercase first",
			contents: `{"Datadir":"/first-data","datadir":"/second-data"}`,
			expected: "/second-data",
		},
		{
			name:     "lowercase first",
			contents: `{"datadir":"/first-data","Datadir":"/second-data"}`,
			expected: "/second-data",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.Datadir,
				"encoding/json applied case-variant duplicate scalar keys in document order, so the last key in the file won")
		})
	}
}

// management-critic-3: NB_DATASTOREENCRYPTIONKEY was never read, so a file without a key always got a generated one persisted.
func TestEnsureEncryptionKeyIgnoresEnvironmentKeyWhenFileHasNone(t *testing.T) {
	const environmentKey = "environment-key"

	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
	}{
		{name: "missing key", contents: `{"HttpConfig":{"AuthAudience":"file-aud"}}`},
		{name: "empty key", contents: `{"DataStoreEncryptionKey":"","HttpConfig":{"AuthAudience":"file-aud"}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NB_DATASTOREENCRYPTIONKEY", environmentKey)
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			cfg, err := loadManagementConfig(configPath)
			require.NoError(t, err)
			assert.Empty(t, cfg.DataStoreEncryptionKey,
				"NB_DATASTOREENCRYPTIONKEY was never read; a file without a key loaded with an empty key")

			require.NoError(t, EnsureEncryptionKey(context.Background(), configPath, cfg))
			assert.NotEmpty(t, cfg.DataStoreEncryptionKey,
				"EnsureEncryptionKey generated a fresh key when the file had none")
			assert.NotEqual(t, environmentKey, cfg.DataStoreEncryptionKey,
				"EnsureEncryptionKey generated a random key instead of adopting the environment value")

			persistedConfig, err := os.ReadFile(configPath)
			require.NoError(t, err)
			var persisted map[string]any
			require.NoError(t, json.Unmarshal(persistedConfig, &persisted))
			persistedKey, _ := persisted["DataStoreEncryptionKey"].(string)
			assert.NotEmpty(t, persistedKey,
				"The generated key was written back to management.json so later starts reuse it")
			assert.NotEqual(t, environmentKey, persistedKey,
				"The persisted key was the generated one, never the environment value")
		})
	}
}

// management-critic-4: a single JSON object where an array of hosts was expected was rejected.
func TestLoadManagementConfigRejectsObjectsForHostSlices(t *testing.T) {
	clearManagementConfigEnvironment(t)

	tests := []struct {
		name     string
		contents string
	}{
		{name: "stuns", contents: `{"Stuns":{"Proto":"udp","URI":"stun:x"}}`},
		{name: "turns", contents: `{"TURNConfig":{"Turns":{"Proto":"udp","URI":"turn:x"}}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "management.json")
			require.NoError(t, os.WriteFile(configPath, []byte(test.contents), 0o600))

			_, err := loadManagementConfig(configPath)
			assert.Error(t, err,
				"encoding/json rejected an object for a []*Host field ('cannot unmarshal object into Go struct field') instead of wrapping it into a one-element slice")
		})
	}
}

func setAdminConfigPath(t *testing.T, configPath string) {
	t.Helper()

	oldConfigPath := nbconfig.MgmtConfigPath
	oldAdminDatadir := adminDatadir
	nbconfig.MgmtConfigPath = configPath
	adminDatadir = ""
	t.Cleanup(func() {
		nbconfig.MgmtConfigPath = oldConfigPath
		adminDatadir = oldAdminDatadir
	})
}

func clearManagementConfigEnvironment(t *testing.T) {
	t.Helper()
	clearManagementEnvironmentType(t, reflect.TypeOf(nbconfig.Config{}), "", make(map[reflect.Type]bool))
}

func clearManagementEnvironmentType(t *testing.T, configType reflect.Type, prefix string, visiting map[reflect.Type]bool) {
	t.Helper()

	for configType.Kind() == reflect.Pointer {
		configType = configType.Elem()
	}
	if configType.Kind() != reflect.Struct || visiting[configType] {
		return
	}
	visiting[configType] = true
	defer delete(visiting, configType)

	for i := range configType.NumField() {
		field := configType.Field(i)
		if !field.IsExported() {
			continue
		}
		key := strings.Split(field.Tag.Get("json"), ",")[0]
		if key == "-" {
			continue
		}
		if key == "" {
			key = field.Name
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		environmentName := "NB_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(key))
		t.Setenv(environmentName, "")
		require.NoError(t, os.Unsetenv(environmentName))
		clearManagementEnvironmentType(t, field.Type, key, visiting)
	}
}

func runManagementPreRun(t *testing.T, httpConfig string, changedFlags map[string]string) int {
	t.Helper()
	return runManagementPreRunWithEnvironment(t, httpConfig, changedFlags, nil)
}

func runManagementPreRunWithEnvironment(t *testing.T, httpConfig string, changedFlags map[string]string, environment map[string]string) int {
	t.Helper()

	for _, name := range []string{
		"NB_DATADIR",
		"NB_DATASTOREENCRYPTIONKEY",
		"NB_HTTPCONFIG_LETSENCRYPTDOMAIN",
		"NB_HTTPCONFIG_CERTFILE",
		"NB_HTTPCONFIG_CERTKEY",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
	for name, value := range environment {
		t.Setenv(name, value)
	}

	configPath := filepath.Join(t.TempDir(), "management.json")
	contents := `{"DataStoreEncryptionKey":"configured-key","HttpConfig":` + httpConfig + `}`
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))

	flags := map[string]*pflag.Flag{
		"port":               mgmtCmd.Flags().Lookup("port"),
		"datadir":            mgmtCmd.Flags().Lookup("datadir"),
		"letsencrypt-domain": mgmtCmd.Flags().Lookup("letsencrypt-domain"),
		"cert-file":          mgmtCmd.Flags().Lookup("cert-file"),
		"cert-key":           mgmtCmd.Flags().Lookup("cert-key"),
	}
	for name, flag := range flags {
		require.NotNil(t, flag, "Management compatibility flag %s should be registered", name)
	}

	oldConfigPath := nbconfig.MgmtConfigPath
	oldCommandContext := mgmtCmd.Context()
	oldMgmtPort := mgmtPort
	oldMgmtDataDir := mgmtDataDir
	oldLogLevel := logLevel
	oldLogFile := logFile
	oldDNSDomain := dnsDomain
	oldLetsencryptDomain := mgmtLetsencryptDomain
	oldCertFile := certFile
	oldCertKey := certKey
	oldConfig := config
	oldFlagStates := make(map[*pflag.Flag]struct {
		value   string
		changed bool
	}, len(flags))
	for _, flag := range flags {
		oldFlagStates[flag] = struct {
			value   string
			changed bool
		}{value: flag.Value.String(), changed: flag.Changed}
	}
	t.Cleanup(func() {
		for flag, state := range oldFlagStates {
			require.NoError(t, flag.Value.Set(state.value))
			flag.Changed = state.changed
		}
		nbconfig.MgmtConfigPath = oldConfigPath
		mgmtCmd.SetContext(oldCommandContext)
		mgmtPort = oldMgmtPort
		mgmtDataDir = oldMgmtDataDir
		logLevel = oldLogLevel
		logFile = oldLogFile
		dnsDomain = oldDNSDomain
		mgmtLetsencryptDomain = oldLetsencryptDomain
		certFile = oldCertFile
		certKey = oldCertKey
		config = oldConfig
	})

	baseline := map[string]string{
		"port":               "80",
		"datadir":            defaultMgmtDataDir,
		"letsencrypt-domain": "",
		"cert-file":          "",
		"cert-key":           "",
	}
	for name, value := range baseline {
		require.NoError(t, flags[name].Value.Set(value))
		flags[name].Changed = false
	}
	for name, value := range changedFlags {
		flag, ok := flags[name]
		require.True(t, ok, "Compatibility scenario should reference a known flag")
		require.NoError(t, flag.Value.Set(value))
		flag.Changed = true
	}

	nbconfig.MgmtConfigPath = configPath
	mgmtCmd.SetContext(context.Background())
	logLevel = "info"
	logFile = "console"
	dnsDomain = defaultSingleAccModeDomain
	require.NoError(t, mgmtCmd.PreRunE(mgmtCmd, nil))
	return mgmtPort
}

func unchangedManagementFlags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("management", pflag.ContinueOnError)
	flags.String("datadir", defaultMgmtDataDir, "")
	flags.String("letsencrypt-domain", "", "")
	flags.String("cert-key", "", "")
	flags.String("cert-file", "", "")
	return flags
}
