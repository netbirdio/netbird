package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigIgnoresEmptyNumericEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	t.Setenv("NB_SERVER_METRICSPORT", "")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig().Server.MetricsPort, cfg.Server.MetricsPort,
		"An empty numeric environment variable should retain the previous default")
}

func TestLoadConfigPreservesLegacyYAMLSemantics(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		wantErr  bool
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name: "wrong case key is ignored",
			contents: `server:
  metricsport: 9191
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9090, cfg.Server.MetricsPort, "YAML field names should remain case-sensitive")
			},
		},
		{
			name: "unknown key is ignored",
			contents: `server:
  unknownSetting: true
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, DefaultConfig().Server, cfg.Server, "Unknown YAML fields should remain ignored")
			},
		},
		{
			name: "null scalar retains initialized default",
			contents: `server:
  metricsPort: null
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9090, cfg.Server.MetricsPort, "Null scalar values should retain initialized defaults")
			},
		},
		{
			name: "empty nested value retains initialized defaults",
			contents: `server:
  auth:
    storage: {}
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "sqlite3", cfg.Server.Auth.Storage.Type,
					"Empty nested values should retain initialized defaults")
			},
		},
		{
			name: "empty pointer object remains present",
			contents: `server:
  auth:
    owner: {}
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.NotNil(t, cfg.Server.Auth.Owner, "An explicitly configured empty object should remain present")
			},
		},
		{
			name: "empty sequence remains non nil",
			contents: `server:
  stunPorts: []
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.NotNil(t, cfg.Server.StunPorts, "An explicitly configured empty sequence should remain non-nil")
				assert.Empty(t, cfg.Server.StunPorts, "An explicitly configured empty sequence should remain empty")
			},
		},
		{
			name: "null sequence becomes nil",
			contents: `server:
  stunPorts: null
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Nil(t, cfg.Server.StunPorts, "A null sequence should retain legacy nil semantics")
			},
		},
		{
			name: "empty map remains non nil",
			contents: `server:
  perAccountSupportedSyncMessageVersions: {}
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.NotNil(t, cfg.Server.PerAccountSupportedSyncMessageVersions,
					"An explicitly configured empty map should remain non-nil")
			},
		},
		{
			name: "map key case is retained",
			contents: `server:
  perAccountSupportedSyncMessageVersions:
    AccountA: 1
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, map[string]int{"AccountA": 1}, cfg.Server.PerAccountSupportedSyncMessageVersions,
					"YAML map keys should retain their case")
			},
		},
		{
			name: "legacy boolean spelling remains accepted",
			contents: `server:
  disableAnonymousMetrics: yes
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.True(t, cfg.Server.DisableAnonymousMetrics, "Legacy YAML booleans should remain accepted")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			if test.wantErr {
				assert.Error(t, err, "Legacy-invalid YAML should remain rejected")
				return
			}
			if !assert.NoError(t, err) {
				return
			}
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigTreatsEveryLegacyFileExtensionAsYAML(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, name := range []string{"config.json", "config.toml"} {
		t.Run(name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, name, `server:
  metricsPort: 9191
`)

			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Combined configuration files were historically decoded as YAML regardless of extension") {
				return
			}
			assert.Equal(t, 9191, cfg.Server.MetricsPort, "YAML content should load regardless of its file extension")
		})
	}
}

func TestLegacyCombinedConfigFlagRemainsRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	require.NotNil(t, flag, "Legacy config flag should remain registered")
	assert.Equal(t, "c", flag.Shorthand, "Legacy config shorthand should remain unchanged")
}

func TestLoadConfigSupportsYAMLWithoutKnownExtension(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, name := range []string{"config", "config.conf"} {
		t.Run(name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, name, `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "yaml-secret"
`)

			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, "yaml-secret", cfg.Server.AuthSecret, "Unknown extensions should remain YAML-compatible")
		})
	}
}

func TestLoadConfigSupportsLegacyYAMLBooleans(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	configPath := writeCombinedConfig(t, "config.yaml", `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
  disableAnonymousMetrics: yes
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.True(t, cfg.Server.DisableAnonymousMetrics, "Legacy YAML boolean values should remain supported")
}

func clearCombinedConfigEnvironment(t *testing.T) {
	t.Helper()
	clearCombinedEnvironmentType(t, reflect.TypeOf(CombinedConfig{}), "", make(map[reflect.Type]bool))
}

func clearCombinedEnvironmentType(t *testing.T, configType reflect.Type, prefix string, visiting map[reflect.Type]bool) {
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
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
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
		clearCombinedEnvironmentType(t, field.Type, key, visiting)
	}
}

func writeCombinedConfig(t *testing.T, name, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))
	return configPath
}

// legacyCombinedServerFile is a minimal file that satisfied Validate on main.
const legacyCombinedServerFile = `server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
`

func TestLoadConfigPreservesLegacyEnvironmentIsNotAConfigSource(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		env      map[string]string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name:     "NB_SERVER_LOGLEVEL does not override file",
			contents: legacyCombinedServerFile + "  logLevel: info\n",
			env:      map[string]string{"NB_SERVER_LOGLEVEL": "debug"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "info", cfg.Server.LogLevel, "Legacy loader consulted no environment variables; the file value must win")
				assert.Equal(t, "info", cfg.Relay.LogLevel, "Legacy relay log level was inherited from the file value")
				assert.Equal(t, "info", cfg.Signal.LogLevel, "Legacy signal log level was inherited from the file value")
				assert.Equal(t, "info", cfg.Management.LogLevel, "Legacy management log level was inherited from the file value")
			},
		},
		{
			name:     "NB_SERVER_AUTHSECRET does not override file",
			contents: legacyCombinedServerFile,
			env:      map[string]string{"NB_SERVER_AUTHSECRET": "env-secret"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "file-secret", cfg.Server.AuthSecret, "Legacy loader consulted no environment variables; the file secret must win")
				assert.Equal(t, "file-secret", cfg.Relay.AuthSecret, "Legacy relay secret was copied from the file value")
			},
		},
		{
			name:     "NB_SERVER_METRICSPORT does not override default",
			contents: legacyCombinedServerFile,
			env:      map[string]string{"NB_SERVER_METRICSPORT": "9191"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader consulted no environment variables; the default must be kept")
			},
		},
		{
			name:     "NB_SERVER_AUTH_ISSUER does not set nested field",
			contents: legacyCombinedServerFile,
			env:      map[string]string{"NB_SERVER_AUTH_ISSUER": "https://idp.example.com"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.Auth.Issuer, "Legacy loader consulted no environment variables for nested fields")
				assert.Empty(t, cfg.Management.Auth.Issuer, "Legacy management auth was not populated from the environment")
			},
		},
		{
			name:     "NB_SERVER_TLS_LETSENCRYPT_DOMAINS does not set list field",
			contents: legacyCombinedServerFile,
			env:      map[string]string{"NB_SERVER_TLS_LETSENCRYPT_DOMAINS": "a.com"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Nil(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy loader consulted no environment variables for list fields")
			},
		},
		{
			name:     "NB_SERVER_LOG_LEVEL with word separator is ignored",
			contents: legacyCombinedServerFile,
			env:      map[string]string{"NB_SERVER_LOG_LEVEL": "debug"},
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "info", cfg.Server.LogLevel, "Legacy loader consulted no environment variables")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyEmptyPathReturnsPlainDefaults(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	t.Setenv("NB_SERVER_EXPOSEDADDRESS", "https://env.example.com")
	t.Setenv("NB_SERVER_AUTHSECRET", "env-secret")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg,
		"Legacy LoadConfig(\"\") returned DefaultConfig() before consulting anything else, including ApplySimplifiedDefaults")
	assert.False(t, cfg.Relay.Enabled, "Legacy empty path never enabled the embedded relay")
	assert.False(t, cfg.Signal.Enabled, "Legacy empty path never enabled the embedded signal")
	assert.False(t, cfg.Management.Enabled, "Legacy empty path never enabled management")
	assert.EqualError(t, cfg.Validate(), "server.exposedAddress is required",
		"Legacy empty path produced a config that failed validation because the environment was not consulted")
}

func TestLoadConfigPreservesLegacyEmptyStringEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		envName  string
		contents string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name:     "empty NB_SERVER_LOGLEVEL keeps log level",
			envName:  "NB_SERVER_LOGLEVEL",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "info", cfg.Server.LogLevel, "Legacy loader ignored the environment; an empty variable must not blank the log level")
				assert.Equal(t, "info", cfg.Relay.LogLevel, "Legacy relay log level inherited info")
				assert.Equal(t, "info", cfg.Management.LogLevel, "Legacy management log level inherited info")
			},
		},
		{
			name:     "empty NB_SERVER_EXPOSEDADDRESS keeps file value",
			envName:  "NB_SERVER_EXPOSEDADDRESS",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "https://netbird.example.com", cfg.Server.ExposedAddress, "Legacy loader ignored the environment; the file exposed address must be kept")
				assert.True(t, cfg.Management.Enabled, "Legacy ApplySimplifiedDefaults ran with the file exposed address")
				assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
			},
		},
		{
			name:     "empty NB_SERVER_DATADIR keeps default",
			envName:  "NB_SERVER_DATADIR",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "/var/lib/netbird/", cfg.Server.DataDir, "Legacy loader ignored the environment; the default data dir must be kept")
				assert.Equal(t, "/var/lib/netbird/", cfg.Management.DataDir, "Legacy management data dir came from the default")
				assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
			},
		},
		{
			name:     "empty NB_SERVER_AUTHSECRET keeps file value",
			envName:  "NB_SERVER_AUTHSECRET",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "file-secret", cfg.Server.AuthSecret, "Legacy loader ignored the environment; the file secret must be kept")
				assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
			},
		},
		{
			name:     "empty NB_SERVER_LISTENADDRESS keeps default",
			envName:  "NB_SERVER_LISTENADDRESS",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, ":443", cfg.Server.ListenAddress, "Legacy loader ignored the environment; the default listen address must be kept")
			},
		},
		{
			name:     "empty NB_SERVER_HEALTHCHECKADDRESS keeps default",
			envName:  "NB_SERVER_HEALTHCHECKADDRESS",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, ":9000", cfg.Server.HealthcheckAddress, "Legacy loader ignored the environment; the default healthcheck address must be kept")
			},
		},
		{
			name:     "empty NB_SERVER_STORE_ENGINE keeps default",
			envName:  "NB_SERVER_STORE_ENGINE",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "sqlite", cfg.Server.Store.Engine, "Legacy loader ignored the environment; the default store engine must be kept")
				assert.Equal(t, "sqlite", cfg.Management.Store.Engine, "Legacy management store engine came from the default")
			},
		},
		{
			name:     "empty NB_SERVER_LOGFILE keeps default",
			envName:  "NB_SERVER_LOGFILE",
			contents: legacyCombinedServerFile,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "console", cfg.Server.LogFile, "Legacy loader ignored the environment; the default console log target must be kept")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, "")
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyUnparsableEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		envName  string
		envValue string
		validate func(*testing.T, *CombinedConfig)
	}{
		{name: "metrics port word", envName: "NB_SERVER_METRICSPORT", envValue: "abc", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader ignored the environment; default metrics port must be kept")
		}},
		{name: "metrics port padded", envName: "NB_SERVER_METRICSPORT", envValue: " 9191 ", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader ignored the environment; default metrics port must be kept")
		}},
		{name: "metrics port float", envName: "NB_SERVER_METRICSPORT", envValue: "9191.0", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader ignored the environment; default metrics port must be kept")
		}},
		{name: "metrics port leading zero", envName: "NB_SERVER_METRICSPORT", envValue: "09090", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader ignored the environment; default metrics port must be kept")
		}},
		{name: "metrics port hex", envName: "NB_SERVER_METRICSPORT", envValue: "0x10", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy loader ignored the environment; default metrics port must be kept")
		}},
		{name: "negative uint", envName: "NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT", envValue: "-1", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, uint(0), cfg.Server.ReverseProxy.TrustedHTTPProxiesCount, "Legacy loader ignored the environment; default proxy count must be kept")
		}},
		{name: "sync version word", envName: "NB_SERVER_SUPPORTEDSYNCMESSAGEVERSIONS", envValue: "x", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.SupportedSyncMessageVersions, "Legacy loader ignored the environment; sync version pointer must remain nil")
		}},
		{name: "boolean word", envName: "NB_SERVER_DISABLEANONYMOUSMETRICS", envValue: "maybe", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.False(t, cfg.Server.DisableAnonymousMetrics, "Legacy loader ignored the environment; default boolean must be kept")
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, test.envValue)
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Legacy loader never failed because of an environment variable") {
				return
			}
			test.validate(t, cfg)
			assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
		})
	}
}

func TestLoadConfigPreservesLegacyEmptyBooleanEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		envName  string
		contents string
		value    func(*CombinedConfig) bool
	}{
		{
			name:     "disableAnonymousMetrics",
			envName:  "NB_SERVER_DISABLEANONYMOUSMETRICS",
			contents: legacyCombinedServerFile + "  disableAnonymousMetrics: true\n",
			value: func(cfg *CombinedConfig) bool {
				return cfg.Server.DisableAnonymousMetrics && cfg.Management.DisableAnonymousMetrics
			},
		},
		{
			name:     "disableGeoliteUpdate",
			envName:  "NB_SERVER_DISABLEGEOLITEUPDATE",
			contents: legacyCombinedServerFile + "  disableGeoliteUpdate: true\n",
			value: func(cfg *CombinedConfig) bool {
				return cfg.Server.DisableGeoliteUpdate && cfg.Management.DisableGeoliteUpdate
			},
		},
		{
			name:     "tls.letsencrypt.enabled",
			envName:  "NB_SERVER_TLS_LETSENCRYPT_ENABLED",
			contents: legacyCombinedServerFile + "  tls:\n    letsencrypt:\n      enabled: true\n",
			value:    func(cfg *CombinedConfig) bool { return cfg.Server.TLS.LetsEncrypt.Enabled },
		},
		{
			name:     "auth.localAuthDisabled",
			envName:  "NB_SERVER_AUTH_LOCALAUTHDISABLED",
			contents: legacyCombinedServerFile + "  auth:\n    localAuthDisabled: true\n",
			value:    func(cfg *CombinedConfig) bool { return cfg.Server.Auth.LocalAuthDisabled },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, "")
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.True(t, test.value(cfg), "Legacy loader ignored the environment; a boolean set to true in the file must stay true")
		})
	}
}

func TestLoadConfigPreservesLegacyBooleanEnvironmentSpellingsIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, value := range []string{"1", "0", "t", "f", "T", "F", "TRUE", "true", "True", "FALSE", "yes", "no", "y", "n", "on", "off", "ON", "Y"} {
		t.Run("default_"+value, func(t *testing.T) {
			t.Setenv("NB_SERVER_DISABLEANONYMOUSMETRICS", value)
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.False(t, cfg.Server.DisableAnonymousMetrics,
				"Legacy booleans came only from YAML or the false default; environment spellings were not consulted")
		})
	}
	for _, value := range []string{"0", "f", "off", "no", "FALSE"} {
		t.Run("file_true_"+value, func(t *testing.T) {
			t.Setenv("NB_SERVER_DISABLEANONYMOUSMETRICS", value)
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  disableAnonymousMetrics: true\n")
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.True(t, cfg.Server.DisableAnonymousMetrics,
				"Legacy booleans came only from YAML; an environment false spelling must not override the file")
		})
	}
}

func TestLoadConfigPreservesLegacyListEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		envName  string
		envValue string
		validate func(*testing.T, *CombinedConfig)
	}{
		{name: "stun ports csv", envName: "NB_SERVER_STUNPORTS", envValue: "3478,3479", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "stun ports csv with space", envName: "NB_SERVER_STUNPORTS", envValue: "3478, 3479", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "stun ports space separated", envName: "NB_SERVER_STUNPORTS", envValue: "3478 3479", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "stun ports trailing comma", envName: "NB_SERVER_STUNPORTS", envValue: "3478,", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "domains csv with space", envName: "NB_SERVER_TLS_LETSENCRYPT_DOMAINS", envValue: "a.com, b.com", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "domains trailing comma", envName: "NB_SERVER_TLS_LETSENCRYPT_DOMAINS", envValue: "a.com,", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "domains quoted", envName: "NB_SERVER_TLS_LETSENCRYPT_DOMAINS", envValue: `"a.com","b.com"`, validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "trusted proxies", envName: "NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIES", envValue: "10.0.0.0/8,192.168.0.0/16", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.ReverseProxy.TrustedHTTPProxies, "Legacy lists were only settable via YAML sequences")
		}},
		{name: "grant types", envName: "NB_SERVER_AUTH_GRANTTYPES", envValue: "authorization_code,refresh_token", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.Auth.GrantTypes, "Legacy lists were only settable via YAML sequences")
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, test.envValue)
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Legacy loader never failed because of an environment variable") {
				return
			}
			test.validate(t, cfg)
			assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
		})
	}
}

func TestLoadConfigPreservesLegacyEmptyListEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		envName  string
		contents string
		validate func(*testing.T, *CombinedConfig)
	}{
		{name: "stun ports with exposed address", envName: "NB_SERVER_STUNPORTS", contents: legacyCombinedServerFile, validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy default STUN ports were kept")
		}},
		{name: "stun ports without exposed address", envName: "NB_SERVER_STUNPORTS", contents: "server: {}\n", validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy default STUN ports were kept even without exposedAddress")
		}},
		{name: "domains", envName: "NB_SERVER_TLS_LETSENCRYPT_DOMAINS", contents: legacyCombinedServerFile, validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy domains stayed nil when absent from the file")
		}},
		{name: "relay addresses", envName: "NB_SERVER_RELAYS_ADDRESSES", contents: legacyCombinedServerFile, validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.Relays.Addresses, "Legacy relay addresses stayed nil when absent from the file")
		}},
		{name: "stuns", envName: "NB_SERVER_STUNS", contents: legacyCombinedServerFile, validate: func(t *testing.T, cfg *CombinedConfig) {
			assert.Nil(t, cfg.Server.Stuns, "Legacy external STUN list stayed nil when absent from the file")
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, "")
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyMapEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, value := range []string{"", "acc=1", `{"acc":1}`} {
		t.Run("value_"+value, func(t *testing.T) {
			t.Setenv("NB_SERVER_PERACCOUNTSUPPORTEDSYNCMESSAGEVERSIONS", value)
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Legacy loader never failed because of an environment variable") {
				return
			}
			assert.Nil(t, cfg.Server.PerAccountSupportedSyncMessageVersions, "Legacy map came only from YAML")
		})
	}
}

func TestLoadConfigPreservesLegacyStunsEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name    string
		envName string
	}{
		{name: "stuns list", envName: "NB_SERVER_STUNS"},
		{name: "stuns uri", envName: "NB_SERVER_STUNS_URI"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, "stun:stun.example.com:3478")
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Legacy loader never failed because of an environment variable") {
				return
			}
			assert.Nil(t, cfg.Server.Stuns, "Legacy external STUN servers were only configurable via YAML")
			assert.True(t, cfg.Relay.Stun.Enabled, "Legacy local STUN stayed enabled")
			assert.Equal(t, []HostConfig{{URI: "stun:netbird.example.com:3478"}}, cfg.Management.Stuns,
				"Legacy clients were pointed at the local STUN server")
		})
	}
}

func TestLoadConfigPreservesLegacyOwnerEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "email and password", env: map[string]string{"NB_SERVER_AUTH_OWNER_EMAIL": "a@b", "NB_SERVER_AUTH_OWNER_PASSWORD": "hash"}},
		{name: "empty email", env: map[string]string{"NB_SERVER_AUTH_OWNER_EMAIL": ""}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.Nil(t, cfg.Server.Auth.Owner, "Legacy owner was nil unless server.auth.owner was present in YAML")
		})
	}
}

func TestLoadConfigPreservesLegacyEmbeddedTopologyIgnoresEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)

	t.Run("relay addresses", func(t *testing.T) {
		t.Setenv("NB_SERVER_RELAYS_ADDRESSES", "rels://r1:443,rels://r2:443")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.True(t, cfg.Relay.Enabled, "Legacy embedded relay stayed enabled because the environment was not consulted")
		assert.Equal(t, []string{"rels://netbird.example.com"}, cfg.Management.Relays.Addresses,
			"Legacy clients were pointed at the embedded relay")
	})

	t.Run("signal uri", func(t *testing.T) {
		t.Setenv("NB_SERVER_SIGNALURI", "https://sig.example.com:443")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.True(t, cfg.Signal.Enabled, "Legacy embedded signal stayed enabled because the environment was not consulted")
		assert.Equal(t, "https://netbird.example.com", cfg.Management.SignalURI,
			"Legacy clients were pointed at the embedded signal")
	})
}

func TestLoadConfigPreservesLegacyStoreEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, name := range []string{"NB_STORE_ENGINE_POSTGRES_DSN", "NB_STORE_ENGINE_SQLITE_FILE", "NB_ACTIVITY_EVENT_STORE_ENGINE", "NB_ACTIVITY_EVENT_POSTGRES_DSN", "NB_ACTIVITY_EVENT_SQLITE_FILE"} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}

	t.Run("store engine and dsn", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_ENGINE", "postgres")
		t.Setenv("NB_SERVER_STORE_DSN", "host=x")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.Equal(t, StoreConfig{Engine: "sqlite"}, cfg.Server.Store, "Legacy store engine came only from YAML")
		assert.Equal(t, StoreConfig{Engine: "sqlite"}, cfg.Management.Store, "Legacy management store came only from YAML")
		applyServerStoreEnv(cfg.Server.Store)
		assert.Empty(t, os.Getenv("NB_STORE_ENGINE_POSTGRES_DSN"), "Legacy chained NB_STORE_ENGINE_POSTGRES_DSN export was derived from the file only")
	})

	t.Run("store file", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_FILE", "/db/x.db")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.Empty(t, cfg.Management.Store.File, "Legacy store file came only from YAML")
		applyServerStoreEnv(cfg.Server.Store)
		assert.Empty(t, os.Getenv("NB_STORE_ENGINE_SQLITE_FILE"), "Legacy chained NB_STORE_ENGINE_SQLITE_FILE export was derived from the file only")
	})

	t.Run("encryption key", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_ENCRYPTIONKEY", "k")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		mgmtConfig, err := cfg.ToManagementConfig()
		require.NoError(t, err)
		assert.Empty(t, mgmtConfig.DataStoreEncryptionKey, "Legacy encryption key came only from YAML, so one was auto-generated")
	})

	t.Run("activity store engine without dsn", func(t *testing.T) {
		t.Setenv("NB_SERVER_ACTIVITYSTORE_ENGINE", "postgres")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.Empty(t, cfg.Server.ActivityStore.Engine, "Legacy activity store engine came only from YAML")
		assert.NoError(t, applyActivityStoreEnv(cfg.Server.ActivityStore), "Legacy startup did not fail on an environment-only activity store engine")
	})

	t.Run("auth store engine without dsn", func(t *testing.T) {
		t.Setenv("NB_SERVER_AUTHSTORE_ENGINE", "postgres")
		configPath := writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		assert.Empty(t, cfg.Server.AuthStore.Engine, "Legacy auth store engine came only from YAML")
		_, err = cfg.ToManagementConfig()
		assert.NoError(t, err, "Legacy management config did not fail on an environment-only auth store engine")
	})
}

func TestLoadConfigPreservesLegacyAdminCommandsIgnoreEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, name := range []string{"NB_STORE_ENGINE_POSTGRES_DSN", "NB_STORE_ENGINE_SQLITE_FILE"} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}

	previousConfigPath := configPath
	previousLevel := log.GetLevel()
	t.Cleanup(func() {
		configPath = previousConfigPath
		log.SetLevel(previousLevel)
	})

	runAdmin := func(t *testing.T) (*CombinedConfig, error) {
		t.Helper()
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		var loaded *CombinedConfig
		err := withAdminConfig(cmd, func(_ context.Context, cfg *CombinedConfig) error {
			loaded = cfg
			return nil
		})
		return loaded, err
	}

	t.Run("store and data dir", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_ENGINE", "postgres")
		t.Setenv("NB_SERVER_STORE_DSN", "host=x")
		t.Setenv("NB_SERVER_DATADIR", "/other")
		configPath = writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  dataDir: /srv/netbird\n")

		cfg, err := runAdmin(t)
		require.NoError(t, err)
		assert.Equal(t, "/srv/netbird", cfg.Management.DataDir, "Legacy admin commands operated on the data dir named in the file")
		assert.Equal(t, StoreConfig{Engine: "sqlite"}, cfg.Management.Store, "Legacy admin commands operated on the store named in the file")
		assert.Empty(t, os.Getenv("NB_STORE_ENGINE_POSTGRES_DSN"), "Legacy admin commands derived NB_STORE_ENGINE_POSTGRES_DSN from the file only")
	})

	t.Run("malformed numeric environment", func(t *testing.T) {
		t.Setenv("NB_SERVER_METRICSPORT", "abc")
		configPath = writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)

		_, err := runAdmin(t)
		assert.NoError(t, err, "Legacy admin commands never failed because of an environment variable")
	})
}

func TestLoadConfigPreservesLegacySectionNamedEnvironmentIgnored(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	const contents = `server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
  tls:
    certFile: /certs/cert.pem
    keyFile: /certs/key.pem
  store:
    engine: postgres
    dsn: host=x
  auth:
    issuer: https://netbird.example.com/oauth2
    owner:
      email: owner@example.com
  relays:
    addresses:
      - rels://r1:443
`
	tests := []struct {
		name     string
		envName  string
		envValue string
	}{
		{name: "NB_SERVER empty", envName: "NB_SERVER", envValue: ""},
		{name: "NB_SERVER_STORE", envName: "NB_SERVER_STORE", envValue: "x"},
		{name: "NB_SERVER_TLS empty", envName: "NB_SERVER_TLS", envValue: ""},
		{name: "NB_SERVER_AUTH", envName: "NB_SERVER_AUTH", envValue: "1"},
		{name: "NB_SERVER_AUTH_OWNER", envName: "NB_SERVER_AUTH_OWNER", envValue: "x"},
		{name: "NB_SERVER_RELAYS", envName: "NB_SERVER_RELAYS", envValue: "x"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, test.envValue)
			configPath := writeCombinedConfig(t, "config.yaml", contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, "https://netbird.example.com", cfg.Server.ExposedAddress, "Legacy file section was decoded regardless of a section-named environment variable")
			assert.Equal(t, "/certs/cert.pem", cfg.Server.TLS.CertFile, "Legacy TLS section was decoded regardless of a section-named environment variable")
			assert.Equal(t, StoreConfig{Engine: "postgres", DSN: "host=x"}, cfg.Server.Store, "Legacy store section was decoded regardless of a section-named environment variable")
			assert.Equal(t, "https://netbird.example.com/oauth2", cfg.Server.Auth.Issuer, "Legacy auth section was decoded regardless of a section-named environment variable")
			if assert.NotNil(t, cfg.Server.Auth.Owner, "Legacy owner section was decoded regardless of a section-named environment variable") {
				assert.Equal(t, "owner@example.com", cfg.Server.Auth.Owner.Email)
			}
			assert.Equal(t, []string{"rels://r1:443"}, cfg.Server.Relays.Addresses, "Legacy relays section was decoded regardless of a section-named environment variable")
			assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
		})
	}
}

func TestLoadConfigPreservesLegacyRootAndListItemKeyCaseSensitivity(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name: "capitalized root key is ignored",
			contents: `Server:
  metricsPort: 9191
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9090, cfg.Server.MetricsPort, "Legacy YAML root keys were case-sensitive")
			},
		},
		{
			name: "uppercase root key is ignored",
			contents: `SERVER:
  exposedAddress: https://netbird.example.com
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.ExposedAddress, "Legacy YAML root keys were case-sensitive")
				assert.EqualError(t, cfg.Validate(), "server.exposedAddress is required", "Legacy startup failed validation")
			},
		},
		{
			name: "wrong case list item key is ignored",
			contents: `server:
  stuns:
    - URI: stun:x:3478
`,
			validate: func(t *testing.T, cfg *CombinedConfig) {
				require.Len(t, cfg.Server.Stuns, 1, "Legacy list item was still created")
				assert.Empty(t, cfg.Server.Stuns[0].URI, "Legacy YAML keys inside list items were case-sensitive")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyMixedCaseDuplicateKeyResolution(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	configPath := writeCombinedConfig(t, "config.yaml", `server:
  metricsPort: 1
  MetricsPort: 2
`)

	for i := 0; i < 25; i++ {
		cfg, err := LoadConfig(configPath)
		require.NoError(t, err)
		if !assert.Equal(t, 1, cfg.Server.MetricsPort,
			"Legacy YAML applied only the exactly matching key deterministically on every load") {
			return
		}
	}
}

func TestLoadConfigTreatsAdditionalLegacyFileExtensionsAsYAML(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, name := range []string{"config.env", "config.dotenv", "config.ini", "config.properties", "config.props", "config.prop", "config.hcl", "config.tfvars", "config.JSON"} {
		t.Run(name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, name, `server:
  metricsPort: 9191
`)

			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Combined configuration files were historically decoded as YAML regardless of extension") {
				return
			}
			assert.Equal(t, 9191, cfg.Server.MetricsPort, "YAML content should load regardless of its file extension")
		})
	}
}

func TestLoadConfigPreservesLegacyStrictYAMLTyping(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
	}{
		{name: "quoted int", contents: "server:\n  metricsPort: \"9191\"\n"},
		{name: "str tagged int", contents: "server:\n  metricsPort: !!str 9191\n"},
		{name: "quoted uint", contents: "server:\n  reverseProxy:\n    trustedHTTPProxiesCount: \"3\"\n"},
		{name: "quoted int pointer", contents: "server:\n  supportedSyncMessageVersions: \"2\"\n"},
		{name: "quoted map value", contents: "server:\n  perAccountSupportedSyncMessageVersions: {abc: \"2\"}\n"},
		{name: "int as bool", contents: "server:\n  disableAnonymousMetrics: 1\n"},
		{name: "float as bool", contents: "server:\n  disableAnonymousMetrics: 1.0\n"},
		{name: "quoted true as bool", contents: "server:\n  disableAnonymousMetrics: \"true\"\n"},
		{name: "quoted zero as bool", contents: "server:\n  disableAnonymousMetrics: \"0\"\n"},
		{name: "t as bool", contents: "server:\n  disableAnonymousMetrics: t\n"},
		{name: "yEs as bool", contents: "server:\n  disableAnonymousMetrics: yEs\n"},
		{name: "scalar into int slice", contents: "server:\n  stunPorts: 3479\n"},
		{name: "csv into int slice", contents: "server:\n  stunPorts: \"3479,3480\"\n"},
		{name: "quoted element in int slice", contents: "server:\n  stunPorts: [3479, \"3480\"]\n"},
		{name: "csv into string slice", contents: "server:\n  tls:\n    letsencrypt:\n      domains: a.com,b.com\n"},
		{name: "empty string into int", contents: "server:\n  metricsPort: \"\"\n"},
		{name: "float overflow into int", contents: "server:\n  metricsPort: 99999999999999999999\n"},
		{name: "int overflow into int", contents: "server:\n  metricsPort: 9223372036854775808\n"},
		{name: "negative into uint", contents: "server:\n  reverseProxy:\n    trustedHTTPProxiesCount: -1\n"},
		{name: "map into struct slice", contents: "server:\n  stuns:\n    uri: stun:x:3478\n"},
		{name: "map into int slice", contents: "server:\n  stunPorts: {}\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			_, err := LoadConfig(configPath)
			if !assert.Error(t, err, "Legacy yaml.v3 decoding rejected values whose YAML type did not match the Go field") {
				return
			}
			assert.ErrorContains(t, err, "cannot unmarshal", "Legacy error came from yaml.v3 strict typing")
		})
	}
}

func TestLoadConfigPreservesLegacyUnquotedStringScalarText(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for _, value := range []string{"0x10", "0755", "0123456789", "1234567890123456789012345", "1.50", "1e3", ".inf", "true", "2001-12-14"} {
		t.Run(value, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", "server:\n  authSecret: "+value+"\n")
			cfg, err := LoadConfig(configPath)
			if !assert.NoError(t, err, "Legacy yaml.v3 decoded any unquoted scalar into a string field") {
				return
			}
			assert.Equal(t, value, cfg.Server.AuthSecret, "Legacy yaml.v3 kept the original scalar text for string fields")
		})
	}
}

func TestLoadConfigPreservesLegacyEmptyIntegerEnvironmentKeepsFileValue(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	const contents = legacyCombinedServerFile + `  reverseProxy:
    trustedHTTPProxiesCount: 3
    accessLogRetentionDays: 30
    accessLogCleanupIntervalHours: 12
`
	tests := []struct {
		name     string
		envName  string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name:    "empty NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT keeps uint from file",
			envName: "NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, uint(3), cfg.Server.ReverseProxy.TrustedHTTPProxiesCount,
					"Legacy loader ignored the environment; an empty variable must not blank the uint proxy count set in the file")
				assert.Equal(t, uint(3), cfg.Management.ReverseProxy.TrustedHTTPProxiesCount,
					"Legacy management reverse proxy was copied from the file because the proxy count was non-zero")
			},
		},
		{
			name:    "empty NB_SERVER_REVERSEPROXY_ACCESSLOGRETENTIONDAYS keeps int from file",
			envName: "NB_SERVER_REVERSEPROXY_ACCESSLOGRETENTIONDAYS",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 30, cfg.Server.ReverseProxy.AccessLogRetentionDays,
					"Legacy loader ignored the environment; an empty variable must not blank the retention days set in the file")
				assert.Equal(t, 30, cfg.Management.ReverseProxy.AccessLogRetentionDays,
					"Legacy management reverse proxy carried the 30 day retention from the file")
			},
		},
		{
			name:    "empty NB_SERVER_REVERSEPROXY_ACCESSLOGCLEANUPINTERVALHOURS keeps int from file",
			envName: "NB_SERVER_REVERSEPROXY_ACCESSLOGCLEANUPINTERVALHOURS",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 12, cfg.Server.ReverseProxy.AccessLogCleanupIntervalHours,
					"Legacy loader ignored the environment; an empty variable must not blank the cleanup interval set in the file")
				assert.Equal(t, 12, cfg.Management.ReverseProxy.AccessLogCleanupIntervalHours,
					"Legacy management reverse proxy carried the 12 hour cleanup interval from the file")
			},
		},
		{
			name:    "empty NB_SERVER_METRICSPORT keeps int from file",
			envName: "NB_SERVER_METRICSPORT",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9191, cfg.Server.MetricsPort,
					"Legacy loader ignored the environment; an empty variable must not blank the metrics port set in the file")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.envName, "")
			configPath := writeCombinedConfig(t, "config.yaml", contents+"  metricsPort: 9191\n")
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
			assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
		})
	}
}

func TestLoadConfigPreservesLegacyNullSequenceItemsAreDropped(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name:     "null stuns item",
			contents: legacyCombinedServerFile + "  stuns:\n    - null\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.Stuns, "Legacy yaml.v3 dropped null sequence items, leaving no external STUN servers")
				assert.True(t, cfg.Relay.Stun.Enabled, "Legacy local STUN stayed enabled because no external STUN server survived decoding")
				assert.Equal(t, []HostConfig{{URI: "stun:netbird.example.com:3478"}}, cfg.Management.Stuns,
					"Legacy clients were pointed at the local STUN server")
			},
		},
		{
			name:     "null relay address item",
			contents: legacyCombinedServerFile + "  relays:\n    addresses:\n      - null\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.Relays.Addresses, "Legacy yaml.v3 dropped null sequence items, leaving no external relay addresses")
				assert.True(t, cfg.Relay.Enabled, "Legacy embedded relay stayed enabled because no external relay address survived decoding")
				assert.Equal(t, []string{"rels://netbird.example.com"}, cfg.Management.Relays.Addresses,
					"Legacy clients were pointed at the embedded relay")
			},
		},
		{
			name:     "null letsencrypt domain item",
			contents: legacyCombinedServerFile + "  tls:\n    letsencrypt:\n      enabled: true\n      dataDir: /le\n      domains:\n        - null\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.TLS.LetsEncrypt.Domains, "Legacy yaml.v3 dropped null sequence items, leaving no Let's Encrypt domains")
				assert.False(t, cfg.HasLetsEncrypt(), "Legacy Let's Encrypt was not considered configured without a surviving domain")
			},
		},
		{
			name:     "null stun port item after a valid port",
			contents: legacyCombinedServerFile + "  stunPorts:\n    - 3478\n    - null\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, []int{3478}, cfg.Server.StunPorts, "Legacy yaml.v3 dropped the null port item and kept only 3478")
				assert.NoError(t, cfg.Validate(), "Legacy config validated because no zero port was retained")
				assert.Equal(t, []int{3478}, cfg.Relay.Stun.Ports, "Legacy local STUN listened only on 3478")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyDottedKeysAreLiteralUnknownKeys(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		validate func(*testing.T, *CombinedConfig)
	}{
		{
			name:     "dotted root key is ignored",
			contents: legacyCombinedServerFile + "server.metricsPort: 1\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, 9090, cfg.Server.MetricsPort,
					"Legacy yaml.v3 matched keys literally; 'server.metricsPort' was an unknown root key and left the default in place")
			},
		},
		{
			name:     "dotted nested key is ignored",
			contents: legacyCombinedServerFile + "  tls.certFile: /a\n  tls.keyFile: /b\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Empty(t, cfg.Server.TLS.CertFile,
					"Legacy yaml.v3 matched keys literally; 'tls.certFile' was an unknown key under server and did not enable file-based TLS")
				assert.Empty(t, cfg.Server.TLS.KeyFile,
					"Legacy yaml.v3 matched keys literally; 'tls.keyFile' was an unknown key under server")
				assert.False(t, cfg.HasTLSCert(), "Legacy file-based TLS stayed disabled")
			},
		},
		{
			name:     "dotted store key is ignored",
			contents: legacyCombinedServerFile + "  store.engine: postgres\n",
			validate: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "sqlite", cfg.Server.Store.Engine,
					"Legacy yaml.v3 matched keys literally; 'store.engine' was an unknown key under server and kept the sqlite default")
				assert.Equal(t, "sqlite", cfg.Management.Store.Engine, "Legacy management store engine came from the default")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, "config.yaml", test.contents)
			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			test.validate(t, cfg)
			assert.NoError(t, cfg.Validate(), "Legacy config remained valid")
		})
	}
}

func TestLoadConfigPreservesLegacyRejectionOfRealTOMLContent(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	configPath := writeCombinedConfig(t, "config.toml", `[server]
exposedAddress = "https://netbird.example.com"
authSecret = "s"
metricsPort = 9191
`)

	_, err := LoadConfig(configPath)
	if !assert.Error(t, err, "Legacy loader always decoded the file as YAML regardless of the .toml extension; a TOML table header parsed as a YAML sequence and was rejected, so the server did not start") {
		return
	}
	assert.ErrorContains(t, err, "failed to parse config file:", "Legacy parse errors were prefixed with 'failed to parse config file:'")
	assert.ErrorContains(t, err, "cannot unmarshal !!seq into cmd.CombinedConfig",
		"Legacy yaml.v3 rejected the TOML table header '[server]' as a sequence at the document root")
}
