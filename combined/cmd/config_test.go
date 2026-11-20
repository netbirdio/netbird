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
	for _, override := range serverEnvOverrides(&ServerConfig{}) {
		t.Setenv(override.env, "")
		require.NoError(t, os.Unsetenv(override.env))
	}
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

func TestLoadConfigLogLevelPrecedence(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name     string
		contents string
		env      string
		want     string
	}{
		{name: "default only", contents: legacyCombinedServerFile, want: "info"},
		{name: "file beats default", contents: legacyCombinedServerFile + "  logLevel: warn\n", want: "warn"},
		{name: "environment beats file", contents: legacyCombinedServerFile + "  logLevel: warn\n", env: "debug", want: "debug"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.env != "" {
				t.Setenv("NB_SERVER_LOGLEVEL", test.env)
			}
			cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", test.contents))
			require.NoError(t, err)
			assert.Equal(t, test.want, cfg.Server.LogLevel, "server.logLevel")
			// The embedded services inherit the resolved level, not the file value.
			assert.Equal(t, test.want, cfg.Relay.LogLevel, "relay log level")
			assert.Equal(t, test.want, cfg.Signal.LogLevel, "signal log level")
			assert.Equal(t, test.want, cfg.Management.LogLevel, "management log level")
		})
	}
}

func TestLoadConfigEnvironmentSetsTaggedFields(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	t.Setenv("NB_SERVER_METRICSPORT", "9191")
	t.Setenv("NB_SERVER_DISABLEANONYMOUSMETRICS", "true")
	t.Setenv("NB_SERVER_TLS_LETSENCRYPT_EMAIL", "acme@example.com")
	t.Setenv("NB_SERVER_AUTH_ISSUER", "https://idp.example.com/oauth2")
	t.Setenv("NB_SERVER_AUTH_OWNER_EMAIL", "owner@example.com")
	t.Setenv("NB_SERVER_AUTH_OWNER_PASSWORD", "hash")
	t.Setenv("NB_SERVER_RELAYS_SECRET", "relay-secret")
	t.Setenv("NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT", "2")
	t.Setenv("NB_SERVER_SUPPORTEDSYNCMESSAGEVERSIONS", "3")
	t.Setenv("NB_SERVER_SIGNALURI", "https://sig.example.com:443")

	cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  metricsPort: 9292\n"))
	require.NoError(t, err)
	assert.Equal(t, 9191, cfg.Server.MetricsPort, "integer from the environment should beat the file")
	assert.True(t, cfg.Server.DisableAnonymousMetrics, "boolean from the environment")
	assert.True(t, cfg.Management.DisableAnonymousMetrics, "boolean should reach management")
	assert.Equal(t, "acme@example.com", cfg.Server.TLS.LetsEncrypt.Email, "nested string from the environment")
	assert.Equal(t, "https://idp.example.com/oauth2", cfg.Management.Auth.Issuer, "auth from the environment should reach management")
	require.NotNil(t, cfg.Server.Auth.Owner, "owner env vars should create the optional owner section")
	assert.Equal(t, AuthOwnerConfig{Email: "owner@example.com", Password: "hash"}, *cfg.Server.Auth.Owner, "owner")
	assert.Equal(t, "relay-secret", cfg.Server.Relays.Secret, "relays secret")
	assert.Equal(t, uint(2), cfg.Server.ReverseProxy.TrustedHTTPProxiesCount, "unsigned integer from the environment")
	require.NotNil(t, cfg.Server.SupportedSyncMessageVersions, "pointer field from the environment")
	assert.Equal(t, 3, *cfg.Server.SupportedSyncMessageVersions, "pointer field value")
	assert.False(t, cfg.Signal.Enabled, "an external signal URI from the environment disables the embedded signal")
	assert.Equal(t, "https://sig.example.com:443", cfg.Management.SignalURI, "clients should be pointed at the external signal")
}

// TestCombinedConfigEnvironmentNames pins the naming rule: NB_ followed by the
// YAML path with dots as underscores, upper-cased, without splitting camelCase.
func TestCombinedConfigEnvironmentNames(t *testing.T) {
	var walk func(configType reflect.Type, prefix string)
	tagged := 0
	walk = func(configType reflect.Type, prefix string) {
		for configType.Kind() == reflect.Pointer {
			configType = configType.Elem()
		}
		for i := range configType.NumField() {
			field := configType.Field(i)
			key := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if key == "-" {
				continue
			}
			path := prefix + key
			if env := field.Tag.Get("env"); env != "" {
				tagged++
				want := "NB_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
				assert.Equal(t, want, env, "env tag of %s", path)
			}
			if indirect := field.Type; indirect.Kind() == reflect.Struct ||
				(indirect.Kind() == reflect.Pointer && indirect.Elem().Kind() == reflect.Struct) {
				walk(indirect, path+".")
			}
		}
	}
	walk(reflect.TypeOf(CombinedConfig{}), "")
	assert.Greater(t, tagged, 0, "at least one field should be tagged")
}

func TestLoadConfigIgnoresUntaggedEnvironmentNames(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		name  string
		env   string
		value string
	}{
		// camelCase is not split into words.
		{name: "word separator", env: "NB_SERVER_LOG_LEVEL", value: "debug"},
		// server.authSecret keeps the relay's NB_AUTH_SECRET as its only name.
		{name: "auth secret path name", env: "NB_SERVER_AUTHSECRET", value: "env-secret"},
		// server.store.dsn keeps NB_STORE_ENGINE_POSTGRES_DSN as its only name.
		{name: "store dsn path name", env: "NB_SERVER_STORE_DSN", value: "host=x"},
		{name: "store encryption key path name", env: "NB_SERVER_STORE_ENCRYPTIONKEY", value: "k"},
		{name: "activity store path name", env: "NB_SERVER_ACTIVITYSTORE_ENGINE", value: "postgres"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.env, test.value)
			cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile))
			require.NoError(t, err)
			assert.Equal(t, "info", cfg.Server.LogLevel, "log level")
			assert.Equal(t, "file-secret", cfg.Server.AuthSecret, "auth secret")
			assert.Equal(t, StoreConfig{Engine: "sqlite"}, cfg.Server.Store, "store")
			assert.Equal(t, StoreConfig{}, cfg.Server.ActivityStore, "activity store")
		})
	}
}

func TestLoadConfigEmptyEnvironmentValues(t *testing.T) {
	clearCombinedConfigEnvironment(t)

	t.Run("tagged string is cleared", func(t *testing.T) {
		t.Setenv("NB_SERVER_LOGFILE", "")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  logFile: /var/log/netbird.log\n"))
		require.NoError(t, err)
		assert.Empty(t, cfg.Server.LogFile, "an explicitly empty tagged variable clears the file value")
	})

	t.Run("override name is ignored", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_ENGINE", "")
		t.Setenv("NB_STORE_ENGINE_POSTGRES_DSN", "")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  store:\n    engine: postgres\n    dsn: host=file\n"))
		require.NoError(t, err)
		assert.Equal(t, StoreConfig{Engine: "postgres", DSN: "host=file"}, cfg.Server.Store, "empty store variables keep the file values")
	})
}

func TestLoadConfigRejectsUnparsableEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	tests := []struct {
		env   string
		value string
	}{
		{env: "NB_SERVER_METRICSPORT", value: "abc"},
		{env: "NB_SERVER_METRICSPORT", value: " 9191 "},
		{env: "NB_SERVER_REVERSEPROXY_TRUSTEDHTTPPROXIESCOUNT", value: "-1"},
		{env: "NB_SERVER_SUPPORTEDSYNCMESSAGEVERSIONS", value: "x"},
		{env: "NB_SERVER_DISABLEANONYMOUSMETRICS", value: "maybe"},
		{env: "NB_SERVER_DISABLEANONYMOUSMETRICS", value: "yes"},
	}

	for _, test := range tests {
		t.Run(test.env+"="+test.value, func(t *testing.T) {
			t.Setenv(test.env, test.value)
			_, err := LoadConfig(writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.env, "the error should name the variable")
		})
	}
}

func TestLoadConfigBooleanEnvironmentSpellings(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	for value, want := range map[string]bool{"1": true, "t": true, "TRUE": true, "True": true, "0": false, "f": false, "FALSE": false} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("NB_SERVER_DISABLEANONYMOUSMETRICS", value)
			contents := legacyCombinedServerFile
			if !want {
				contents += "  disableAnonymousMetrics: true\n"
			}
			cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", contents))
			require.NoError(t, err)
			assert.Equal(t, want, cfg.Server.DisableAnonymousMetrics, "strconv.ParseBool spelling should beat the file")
		})
	}
}

func TestLoadConfigEnvironmentWithoutFile(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	t.Setenv("NB_SERVER_EXPOSEDADDRESS", "https://env.example.com")
	t.Setenv(envRelayAuthSecret, "env-secret")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate(), "the environment alone should produce a valid config")
	assert.True(t, cfg.Management.Enabled, "simplified defaults should run on the environment values")
	assert.Equal(t, "rels://env.example.com", cfg.Relay.ExposedAddress, "relay address should derive from the environment")
}

func TestLoadConfigStoreEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)
	const storeFile = legacyCombinedServerFile + `  store:
    engine: sqlite
    dsn: host=file
    file: /file/store.db
  activityStore:
    engine: sqlite
    file: /file/events.db
  accessLogStore:
    engine: sqlite
`

	t.Run("main store", func(t *testing.T) {
		t.Setenv("NB_SERVER_STORE_ENGINE", "postgres")
		t.Setenv("NB_STORE_ENGINE_POSTGRES_DSN", "host=env")
		t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", "/env/store.db")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		assert.Equal(t, StoreConfig{Engine: "postgres", DSN: "host=env", File: "/env/store.db"}, cfg.Server.Store, "environment should beat the file")
		assert.Equal(t, "postgres", cfg.Management.Store.Engine, "management should use the environment engine")
		applyServerStoreEnv(cfg.Server.Store)
		assert.Equal(t, "host=env", os.Getenv("NB_STORE_ENGINE_POSTGRES_DSN"), "the export should keep the environment value")
	})

	t.Run("main store file value is exported", func(t *testing.T) {
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		applyServerStoreEnv(cfg.Server.Store)
		assert.Equal(t, "/file/store.db", os.Getenv("NB_STORE_ENGINE_SQLITE_FILE"), "without an environment value the file value is exported")
	})

	t.Run("activity store", func(t *testing.T) {
		t.Setenv("NB_ACTIVITY_EVENT_SQLITE_FILE", "/env/events.db")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		assert.Equal(t, "/env/events.db", cfg.Server.ActivityStore.File, "environment should beat the file")
	})

	t.Run("activity store postgres without dsn", func(t *testing.T) {
		t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE", "postgres")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		assert.Error(t, applyActivityStoreEnv(cfg.Server.ActivityStore), "an environment engine is validated like a file engine")
	})

	t.Run("access log store", func(t *testing.T) {
		t.Setenv("NB_ACCESS_LOG_STORE_ENGINE", "postgres")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		assert.Equal(t, "postgres", cfg.Server.AccessLogStore.Engine, "environment should beat the file")
	})

	t.Run("auth store", func(t *testing.T) {
		t.Setenv("NB_SERVER_AUTHSTORE_ENGINE", "postgres")
		cfg, err := LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		_, err = cfg.ToManagementConfig()
		assert.ErrorContains(t, err, "authStore.dsn is required", "an environment engine is validated like a file engine")

		t.Setenv("NB_SERVER_AUTHSTORE_DSN", "host=auth")
		cfg, err = LoadConfig(writeCombinedConfig(t, "config.yaml", storeFile))
		require.NoError(t, err)
		mgmt, err := cfg.ToManagementConfig()
		require.NoError(t, err)
		assert.Equal(t, "host=auth", mgmt.EmbeddedIdP.Storage.Config.DSN, "auth store DSN from the environment")
	})
}

func TestAdminCommandsReadEnvironment(t *testing.T) {
	clearCombinedConfigEnvironment(t)
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

	t.Run("data dir", func(t *testing.T) {
		t.Setenv("NB_SERVER_DATADIR", "/other")
		configPath = writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile+"  dataDir: /srv/netbird\n")
		cfg, err := runAdmin(t)
		require.NoError(t, err)
		assert.Equal(t, "/other", cfg.Management.DataDir, "admin commands should operate on the environment data dir")
	})

	t.Run("malformed numeric environment", func(t *testing.T) {
		t.Setenv("NB_SERVER_METRICSPORT", "abc")
		configPath = writeCombinedConfig(t, "config.yaml", legacyCombinedServerFile)
		_, err := runAdmin(t)
		assert.ErrorContains(t, err, "NB_SERVER_METRICSPORT", "admin commands should fail on an unparsable variable")
	})
}
