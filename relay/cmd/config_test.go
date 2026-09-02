package cmd

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleConfig(t *testing.T) {
	clearRelayConfigEnvironment(t)
	require.NoError(t, rootCmd.ParseFlags(nil))
	oldConfigPath := configPath
	configPath = filepath.Join("..", "config.example.yaml")
	t.Cleanup(func() {
		configPath = oldConfigPath
	})

	cfg, err := loadConfig(rootCmd)
	require.NoError(t, err)
	assert.Equal(t, "rels://relay.example.com:443", cfg.ExposedAddress, "Example config should load")
	assert.True(t, cfg.EnableSTUN, "Example config should enable STUN")
}

func TestLoadConfigPreservesLegacyEffectiveDefaults(t *testing.T) {
	clearRelayConfigEnvironment(t)

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	cfg.LetsencryptDomains = nil
	assert.Equal(t, defaultConfig(), cfg, "Relay effective defaults should remain unchanged")
}

func TestLoadConfigPreservesLegacyEnvironmentBindings(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_LISTEN_ADDRESS", ":7443")
	t.Setenv("NB_EXPOSED_ADDRESS", "rels://relay.example.com:443")
	t.Setenv("NB_METRICS_PORT", "9191")
	t.Setenv("NB_LETSENCRYPT_EMAIL", "admin@example.com")
	t.Setenv("NB_LETSENCRYPT_DATA_DIR", "/var/lib/relay/certs")
	t.Setenv("NB_LETSENCRYPT_DOMAINS", "relay.example.com,relay-alt.example.com")
	t.Setenv("NB_LETSENCRYPT_AWS_ROUTE53", "true")
	t.Setenv("NB_TLS_CERT_FILE", "/etc/relay/tls.crt")
	t.Setenv("NB_TLS_KEY_FILE", "/etc/relay/tls.key")
	t.Setenv("NB_AUTH_SECRET", "relay-secret")
	t.Setenv("NB_LOG_LEVEL", "debug")
	t.Setenv("NB_LOG_FILE", "/var/log/relay.log")
	t.Setenv("NB_HEALTH_LISTEN_ADDRESS", ":9001")
	t.Setenv("NB_TRUSTED_PROXIES", "192.0.2.0/24")
	t.Setenv("NB_ENABLE_STUN", "true")
	t.Setenv("NB_STUN_PORTS", "3479,3480")
	t.Setenv("NB_STUN_LOG_LEVEL", "trace")

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Equal(t, &Config{
		ListenAddress:            ":7443",
		ExposedAddress:           "rels://relay.example.com:443",
		MetricsPort:              9191,
		LetsencryptEmail:         "admin@example.com",
		LetsencryptDataDir:       "/var/lib/relay/certs",
		LetsencryptDomains:       []string{"relay.example.com", "relay-alt.example.com"},
		LetsencryptAWSRoute53:    true,
		TlsCertFile:              "/etc/relay/tls.crt",
		TlsKeyFile:               "/etc/relay/tls.key",
		AuthSecret:               "relay-secret",
		LogLevel:                 "debug",
		LogFile:                  "/var/log/relay.log",
		HealthcheckListenAddress: ":9001",
		TrustedProxies:           "192.0.2.0/24",
		EnableSTUN:               true,
		STUNPorts:                []int{3479, 3480},
		STUNLogLevel:             "trace",
	}, cfg, "Every legacy Relay environment binding should remain supported")
}

func TestLoadConfigPreservesLegacyEnvironmentParsing(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		validate func(*testing.T, *Config)
	}{
		{
			name:    "invalid integer becomes zero",
			envName: "NB_METRICS_PORT",
			value:   "invalid",
			validate: func(t *testing.T, cfg *Config) {
				assert.Zero(t, cfg.MetricsPort, "Invalid legacy integer input should retain its parsed zero value")
			},
		},
		{
			name:    "legacy boolean spelling remains false",
			envName: "NB_ENABLE_STUN",
			value:   "yes",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.EnableSTUN, "Unsupported legacy boolean spelling should remain disabled")
			},
		},
		{
			name:    "invalid boolean remains false",
			envName: "NB_ENABLE_STUN",
			value:   "invalid",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.EnableSTUN, "Invalid legacy boolean input should retain its default")
			},
		},
		{
			name:    "empty integer list retains default",
			envName: "NB_STUN_PORTS",
			value:   "",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []int{3478}, cfg.STUNPorts, "Empty legacy integer lists should retain their default")
			},
		},
		{
			name:    "trailing comma integer list retains default",
			envName: "NB_STUN_PORTS",
			value:   "3479,",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []int{3478}, cfg.STUNPorts, "Invalid legacy integer lists should retain their default")
			},
		},
		{
			name:    "quoted comma in string list",
			envName: "NB_LETSENCRYPT_DOMAINS",
			value:   `"relay,one.example.com",relay-two.example.com`,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"relay,one.example.com", "relay-two.example.com"}, cfg.LetsencryptDomains,
					"Legacy string lists should retain CSV quoting")
			},
		},
		{
			name:    "malformed quoted string list is ignored",
			envName: "NB_LETSENCRYPT_DOMAINS",
			value:   `"relay.example.com`,
			validate: func(t *testing.T, cfg *Config) {
				assert.Nil(t, cfg.LetsencryptDomains, "Malformed legacy string lists should retain their default")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv(test.envName, test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			if !assert.NoError(t, err, "Legacy environment parse errors should not abort Relay startup") {
				return
			}
			test.validate(t, cfg)
		})
	}
}

func TestLegacyRelayFlagsRemainRegistered(t *testing.T) {
	expected := map[string]string{
		"listen-address":          "l",
		"exposed-address":         "e",
		"metrics-port":            "",
		"letsencrypt-data-dir":    "d",
		"letsencrypt-domains":     "a",
		"letsencrypt-email":       "",
		"letsencrypt-aws-route53": "",
		"tls-cert-file":           "c",
		"tls-key-file":            "k",
		"auth-secret":             "s",
		"log-level":               "",
		"log-file":                "",
		"health-listen-address":   "H",
		"trusted-proxies":         "",
		"enable-stun":             "",
		"stun-ports":              "",
		"stun-log-level":          "",
	}

	for name, shorthand := range expected {
		flag := rootCmd.Flags().Lookup(name)
		require.NotNil(t, flag, "Legacy flag %s should remain registered", name)
		assert.Equal(t, shorthand, flag.Shorthand, "Legacy shorthand for %s should remain unchanged", name)
	}
}

func TestLoadConfigPrecedence(t *testing.T) {
	clearRelayConfigEnvironment(t)
	path := filepath.Join(t.TempDir(), "relay.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listenAddress: ":8443"
exposedAddress: "relay.example.com:443"
authSecret: file-secret
metricsPort: 9091
enableSTUN: true
stunPorts: [3478, 3479]
`), 0o600))
	t.Setenv("NB_METRICS_PORT", "9191")
	require.NoError(t, rootCmd.ParseFlags(nil))

	listenFlag := rootCmd.Flags().Lookup("listen-address")
	oldListen := listenFlag.Value.String()
	oldChanged := listenFlag.Changed
	t.Cleanup(func() {
		require.NoError(t, listenFlag.Value.Set(oldListen))
		listenFlag.Changed = oldChanged
	})
	require.NoError(t, listenFlag.Value.Set(":7443"))
	listenFlag.Changed = true

	oldConfigPath := configPath
	configPath = path
	t.Cleanup(func() {
		configPath = oldConfigPath
	})

	cfg, err := loadConfig(rootCmd)
	require.NoError(t, err)
	assert.Equal(t, ":7443", cfg.ListenAddress, "Flags should override the configuration file")
	assert.Equal(t, 9191, cfg.MetricsPort, "Environment should override the configuration file")
	assert.Equal(t, "relay.example.com:443", cfg.ExposedAddress, "File values should override defaults")
	assert.True(t, cfg.EnableSTUN, "STUN should be configurable from the file")
	assert.Equal(t, []int{3478, 3479}, cfg.STUNPorts, "STUN ports should load from the file")
}

func loadRelayConfigWithoutFile(t *testing.T) (*Config, error) {
	t.Helper()

	require.NoError(t, rootCmd.ParseFlags(nil))
	oldConfigPath := configPath
	configPath = ""
	t.Cleanup(func() {
		configPath = oldConfigPath
	})
	return loadConfig(rootCmd)
}

func clearRelayConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"NB_LISTEN_ADDRESS",
		"NB_EXPOSED_ADDRESS",
		"NB_METRICS_PORT",
		"NB_LETSENCRYPT_EMAIL",
		"NB_LETSENCRYPT_DATA_DIR",
		"NB_LETSENCRYPT_DOMAINS",
		"NB_LETSENCRYPT_AWS_ROUTE53",
		"NB_TLS_CERT_FILE",
		"NB_TLS_KEY_FILE",
		"NB_AUTH_SECRET",
		"NB_LOG_LEVEL",
		"NB_LOG_FILE",
		"NB_HEALTH_LISTEN_ADDRESS",
		"NB_TRUSTED_PROXIES",
		"NB_ENABLE_STUN",
		"NB_STUN_PORTS",
		"NB_STUN_LOG_LEVEL",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

func TestLoadConfigPreservesLegacyIntegerOverflowParsing(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_METRICS_PORT", "99999999999999999999")

	cfg, err := loadRelayConfigWithoutFile(t)
	if !assert.NoError(t, err, "Legacy pflag stored the clamped integer and only logged the range error, so loading continued") {
		return
	}
	assert.Equal(t, math.MaxInt64, cfg.MetricsPort,
		"Legacy strconv.ParseInt range errors left math.MaxInt64 in the metrics port instead of aborting startup")
}

func TestLoadConfigPreservesLegacyRoute53BooleanSpelling(t *testing.T) {
	for _, value := range []string{"yes", "y", "on", "YES", "On"} {
		t.Run(value, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_LETSENCRYPT_AWS_ROUTE53", value)

			cfg, err := loadRelayConfigWithoutFile(t)
			if !assert.NoError(t, err, "Legacy boolean parse errors should not abort Relay startup") {
				return
			}
			assert.False(t, cfg.LetsencryptAWSRoute53,
				"Legacy strconv.ParseBool rejected %q, leaving Route 53 disabled so the Route 53 TLS branch was never taken", value)
		})
	}
}

func TestLoadConfigPreservesLegacyRoute53InvalidBoolean(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "invalid word", value: "invalid"},
		{name: "numeric two", value: "2"},
		{name: "mixed case true", value: "tRuE"},
		{name: "trailing space", value: "true "},
		{name: "enabled", value: "enabled"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_LETSENCRYPT_AWS_ROUTE53", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			if !assert.NoError(t, err, "Legacy invalid boolean input was logged at Info and ignored, not fatal") {
				return
			}
			assert.False(t, cfg.LetsencryptAWSRoute53,
				"Legacy strconv.ParseBool rejected %q and pflag stored false, so Relay started with Route 53 disabled", test.value)
		})
	}
}

func TestLoadConfigPreservesLegacySTUNPortListRejection(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "non-numeric trailing element", value: "3479,abc"},
		{name: "non-numeric single element", value: "abc"},
		{name: "space after comma", value: "3479, 3480"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_STUN_PORTS", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			if !assert.NoError(t, err, "Legacy integer list parse errors were logged at Info and ignored, not fatal") {
				return
			}
			assert.Equal(t, []int{3478}, cfg.STUNPorts,
				"Legacy pflag intSlice ran strconv.Atoi on every element and rejected the whole value %q, retaining the default", test.value)
		})
	}
}

func TestLoadConfigPreservesLegacySTUNPortDecimalParsing(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected []int
	}{
		{name: "leading zero", value: "010", expected: []int{10}},
		{name: "double leading zero", value: "0010", expected: []int{10}},
		{name: "leading zero element", value: "3478,010", expected: []int{3478, 10}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_STUN_PORTS", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.STUNPorts,
				"Legacy pflag intSlice used strconv.Atoi (base 10 only), so leading zeros were decimal and never octal")
		})
	}
}

func TestLoadConfigPreservesLegacySTUNPortStrictDecimalSyntax(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "hex prefix", value: "0x10"},
		{name: "underscore separator", value: "3_479"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_STUN_PORTS", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			if !assert.NoError(t, err, "Legacy integer list parse errors were logged at Info and ignored, not fatal") {
				return
			}
			assert.Equal(t, []int{3478}, cfg.STUNPorts,
				"Legacy strconv.Atoi rejected %q (no hex prefix or underscores), so the default STUN port list was retained", test.value)
		})
	}
}

func TestLoadConfigPreservesLegacyNewlineInDomainList(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_LETSENCRYPT_DOMAINS", "a.example.com\nb.example.com")

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.example.com"}, cfg.LetsencryptDomains,
		"Legacy pflag readAsCSV performed a single csv.Reader.Read, so only the first line of a newline separated value was used")
}

func TestLoadConfigPreservesLegacyEnvAndFlagDomainAppend(t *testing.T) {
	tests := []struct {
		name       string
		flagValues []string
		expected   []string
	}{
		{
			name:       "single flag value",
			flagValues: []string{"b.example.com"},
			expected:   []string{"a.example.com", "b.example.com"},
		},
		{
			name:       "repeated flag values",
			flagValues: []string{"b.example.com", "c.example.com"},
			expected:   []string{"a.example.com", "b.example.com", "c.example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_LETSENCRYPT_DOMAINS", "a.example.com")
			setRelaySliceFlag(t, "letsencrypt-domains", test.flagValues)

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.LetsencryptDomains,
				"Legacy applied NB_LETSENCRYPT_DOMAINS via flags.Set before argv parsing, so command line domains were appended to the environment list")
		})
	}
}

func TestLoadConfigPreservesLegacyEnvAndFlagSTUNPortAppend(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_STUN_PORTS", "3479")
	setRelaySliceFlag(t, "stun-ports", []string{"3480"})

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Equal(t, []int{3479, 3480}, cfg.STUNPorts,
		"Legacy applied NB_STUN_PORTS via flags.Set before argv parsing, so --stun-ports appended to the environment list and both UDP ports were bound")
}

func TestLoadConfigPreservesLegacyDuplicateSTUNPortFromEnvAndFlag(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_EXPOSED_ADDRESS", "rels://relay.example.com:443")
	t.Setenv("NB_AUTH_SECRET", "relay-secret")
	t.Setenv("NB_ENABLE_STUN", "true")
	t.Setenv("NB_STUN_PORTS", "3478")
	setRelaySliceFlag(t, "stun-ports", []string{"3478"})

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Equal(t, []int{3478, 3478}, cfg.STUNPorts,
		"Legacy appended the --stun-ports value to the NB_STUN_PORTS value, producing a duplicated port list")

	err = cfg.Validate()
	if assert.Error(t, err, "Legacy Validate rejected the duplicated STUN port list and Relay exited") {
		assert.Contains(t, err.Error(), "duplicate STUN port 3478", "Legacy reported the duplicate STUN port")
	}
}

func TestLoadConfigPreservesLegacyEnvironmentNameMatching(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "listen address alias does not outrank legacy name",
			env:  map[string]string{"NB_LISTENADDRESS": ":1", "NB_LISTEN_ADDRESS": ":2"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, ":2", cfg.ListenAddress,
					"Legacy only read NB_LISTEN_ADDRESS; the un-underscored NB_LISTENADDRESS was ignored")
			},
		},
		{
			name: "healthcheck alias is ignored",
			env:  map[string]string{"NB_HEALTHCHECKLISTENADDRESS": ":1"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, ":9000", cfg.HealthcheckListenAddress,
					"Legacy only read NB_HEALTH_LISTEN_ADDRESS; NB_HEALTHCHECKLISTENADDRESS was ignored and the default retained")
			},
		},
		{
			name: "stun ports alias is ignored",
			env:  map[string]string{"NB_STUNPORTS": "1111"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []int{3478}, cfg.STUNPorts,
					"Legacy only read NB_STUN_PORTS; NB_STUNPORTS was ignored and the default retained")
			},
		},
		{
			name: "auth secret alias is ignored",
			env:  map[string]string{"NB_AUTHSECRET": "alias-secret"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.AuthSecret,
					"Legacy only read NB_AUTH_SECRET; NB_AUTHSECRET was ignored")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLoadConfigPreservesLegacyValuesWithEmptyEnvironmentAliases(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "empty log level alias keeps default",
			env:  map[string]string{"NB_LOGLEVEL": ""},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "info", cfg.LogLevel,
					"Legacy never read NB_LOGLEVEL, so an empty alias could not blank the log level and break InitLog")
			},
		},
		{
			name: "empty listen address alias keeps legacy name",
			env:  map[string]string{"NB_LISTENADDRESS": "", "NB_LISTEN_ADDRESS": ":2"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, ":2", cfg.ListenAddress,
					"Legacy never read NB_LISTENADDRESS, so NB_LISTEN_ADDRESS remained effective")
			},
		},
		{
			name: "empty healthcheck alias keeps legacy name",
			env:  map[string]string{"NB_HEALTHCHECKLISTENADDRESS": "", "NB_HEALTH_LISTEN_ADDRESS": ":1"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, ":1", cfg.HealthcheckListenAddress,
					"Legacy never read NB_HEALTHCHECKLISTENADDRESS, so NB_HEALTH_LISTEN_ADDRESS remained effective")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

func TestLegacyRelayHasNoConfigFlag(t *testing.T) {
	require.NoError(t, rootCmd.ParseFlags(nil))

	configFlag := rootCmd.Flags().Lookup("config")
	assert.Nil(t, configFlag, "Legacy Relay registered no --config flag, so --help did not list it")

	if configFlag != nil {
		oldValue := configFlag.Value.String()
		oldChanged := configFlag.Changed
		oldConfigPath := configPath
		t.Cleanup(func() {
			require.NoError(t, configFlag.Value.Set(oldValue))
			configFlag.Changed = oldChanged
			configPath = oldConfigPath
		})
	}

	err := rootCmd.ParseFlags([]string{"--config", filepath.Join(t.TempDir(), "relay.yaml")})
	if assert.Error(t, err, "Legacy Relay rejected --config on the command line and exited with 'failed to execute command'") {
		assert.Contains(t, err.Error(), "unknown flag: --config", "Legacy cobra reported --config as an unknown flag")
	}
}

func TestLoadConfigPreservesLegacyNBConfigIgnored(t *testing.T) {
	clearRelayConfigEnvironment(t)
	path := filepath.Join(t.TempDir(), "relay.yaml")
	require.NoError(t, os.WriteFile(path, []byte("authSecret: file-secret\n"), 0o600))
	t.Setenv("NB_CONFIG", path)

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Empty(t, cfg.AuthSecret, "Legacy Relay never read NB_CONFIG, so no configuration file was loaded from it")
}

func TestLoadConfigPreservesLegacyNilDomainsDefault(t *testing.T) {
	clearRelayConfigEnvironment(t)

	cfg, err := loadRelayConfigWithoutFile(t)
	require.NoError(t, err)
	assert.Nil(t, cfg.LetsencryptDomains,
		"Legacy left LetsencryptDomains nil when neither NB_LETSENCRYPT_DOMAINS nor --letsencrypt-domains was given, and Route53TLS.Domains received nil")
}

func TestLoadConfigPreservesLegacyEnvironmentParseDiagnostics(t *testing.T) {
	clearRelayConfigEnvironment(t)
	t.Setenv("NB_METRICS_PORT", "abc")

	logger := log.StandardLogger()
	oldOutput := logger.Out
	oldLevel := logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(log.TraceLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetLevel(oldLevel)
	})

	_, err := loadRelayConfigWithoutFile(t)
	assert.NoError(t, err, "Legacy rejected environment values were logged and ignored; startup continued")
	assert.Contains(t, logs.String(), "unable to configure flag metrics-port using variable NB_METRICS_PORT",
		"Legacy emitted an Info diagnostic naming the flag and the NB_ variable when an environment value was rejected")
}

func setRelaySliceFlag(t *testing.T, name string, values []string) {
	t.Helper()

	require.NoError(t, rootCmd.ParseFlags(nil))
	flag := rootCmd.Flags().Lookup(name)
	require.NotNil(t, flag, "flag %s should be registered", name)
	sliceValue, ok := flag.Value.(pflag.SliceValue)
	require.True(t, ok, "flag %s should be a slice flag", name)

	oldValues := sliceValue.GetSlice()
	oldChanged := flag.Changed
	t.Cleanup(func() {
		require.NoError(t, sliceValue.Replace(oldValues))
		flag.Changed = oldChanged
	})
	require.NoError(t, sliceValue.Replace(values))
	flag.Changed = true
}

func TestLoadConfigPreservesLegacyQuotedDomainListElements(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected []string
	}{
		{name: "single quoted element", value: `"relay.example.com"`, expected: []string{"relay.example.com"}},
		{name: "quoted trailing element", value: `a.example.com,"b.example.com"`, expected: []string{"a.example.com", "b.example.com"}},
		{name: "csv escaped double quote", value: `"a""b"`, expected: []string{`a"b`}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_LETSENCRYPT_DATA_DIR", "/var/lib/relay/certs")
			t.Setenv("NB_LETSENCRYPT_DOMAINS", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.LetsencryptDomains,
				"Legacy pflag readAsCSV used encoding/csv, which stripped surrounding quotes and unescaped doubled quotes in %q, so the Let's Encrypt host whitelist held the clean hostname", test.value)
			assert.True(t, cfg.HasLetsEncrypt(), "Legacy still entered the Let's Encrypt path for a quoted domain list")
		})
	}
}

func TestLoadConfigPreservesLegacyTrailingNewlineInDomainList(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected []string
	}{
		{name: "single domain", value: "relay.example.com\n", expected: []string{"relay.example.com"}},
		{name: "multiple domains", value: "a.example.com,b.example.com\n", expected: []string{"a.example.com", "b.example.com"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearRelayConfigEnvironment(t)
			t.Setenv("NB_LETSENCRYPT_DATA_DIR", "/var/lib/relay/certs")
			t.Setenv("NB_LETSENCRYPT_DOMAINS", test.value)

			cfg, err := loadRelayConfigWithoutFile(t)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.LetsencryptDomains,
				"Legacy pflag readAsCSV let csv.Reader.Read consume the trailing newline in %q as the record terminator, so the Let's Encrypt host whitelist held the clean hostname without a newline", test.value)
			assert.True(t, cfg.HasLetsEncrypt(), "Legacy still entered the Let's Encrypt path for a newline terminated domain list")
		})
	}
}
