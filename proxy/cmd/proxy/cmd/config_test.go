package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/trustedproxy"
)

func TestExampleConfig(t *testing.T) {
	clearProxyConfigEnvironment(t)
	cmd := newLegacyProxyCommand(t)
	cfg, err := loadConfig(cmd, filepath.Join("..", "..", "..", "config.example.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "proxy.example.com", cfg.ProxyURL, "Example config should load")
}

func TestLoadConfigPreservesLegacyDefaults(t *testing.T) {
	clearProxyConfigEnvironment(t)
	cmd := newLegacyProxyCommand(t)

	cfg, err := loadConfig(cmd, "")
	require.NoError(t, err)
	assert.Equal(t, legacyProxyDefaults(t), cfg, "Proxy defaults should remain unchanged")
}

func TestLoadConfigPreservesLegacyEnvironmentBindings(t *testing.T) {
	clearProxyConfigEnvironment(t)
	t.Setenv("NB_PROXY_LOG_LEVEL", "debug")
	t.Setenv("NB_PROXY_ADDRESS", ":8443")
	t.Setenv("NB_PROXY_MANAGEMENT_ADDRESS", "https://management.example.com:443")
	t.Setenv("NB_PROXY_DOMAIN", "proxy.example.com")
	t.Setenv("NB_PROXY_TOKEN", "proxy-token")
	t.Setenv("NB_PROXY_CERTIFICATE_DIRECTORY", "/var/lib/proxy/certs")
	t.Setenv("NB_PROXY_CERTIFICATE_FILE", "proxy.crt")
	t.Setenv("NB_PROXY_CERTIFICATE_KEY_FILE", "proxy.key")
	t.Setenv("NB_PROXY_ACME_CERTIFICATES", "true")
	t.Setenv("NB_PROXY_ACME_ADDRESS", ":8080")
	t.Setenv("NB_PROXY_ACME_DIRECTORY", "https://acme.example.com/directory")
	t.Setenv("NB_PROXY_ACME_EAB_KID", "eab-kid")
	t.Setenv("NB_PROXY_ACME_EAB_HMAC_KEY", "eab-hmac")
	t.Setenv("NB_PROXY_ACME_CHALLENGE_TYPE", "http-01")
	t.Setenv("NB_PROXY_CERT_LOCK_METHOD", "flock")
	t.Setenv("NB_PROXY_WILDCARD_CERT_DIR", "/var/lib/proxy/wildcards")
	t.Setenv("NB_PROXY_DEBUG_ENDPOINT", "true")
	t.Setenv("NB_PROXY_DEBUG_ENDPOINT_ADDRESS", "localhost:9444")
	t.Setenv("NB_PROXY_HEALTH_ADDRESS", "localhost:9080")
	t.Setenv("NB_PROXY_FORWARDED_PROTO", "https")
	t.Setenv("NB_PROXY_TRUSTED_PROXIES", "192.0.2.0/24")
	t.Setenv("NB_PROXY_WG_PORT", "51820")
	t.Setenv("NB_PROXY_PROXY_PROTOCOL", "true")
	t.Setenv("NB_PROXY_PRESHARED_KEY", "pre-shared-key")
	t.Setenv("NB_PROXY_SUPPORTS_CUSTOM_PORTS", "false")
	t.Setenv("NB_PROXY_REQUIRE_SUBDOMAIN", "true")
	t.Setenv("NB_PROXY_PRIVATE", "true")
	t.Setenv("NB_PROXY_MAX_DIAL_TIMEOUT", "5s")
	t.Setenv("NB_PROXY_MAX_SESSION_IDLE_TIMEOUT", "10m")
	t.Setenv("NB_PROXY_MAPPING_BATCH_WATCHDOG", "30s")
	t.Setenv("NB_PROXY_GEO_DATA_DIR", "/var/lib/proxy/geo")
	t.Setenv("NB_PROXY_CROWDSEC_API_URL", "https://crowdsec.example.com")
	t.Setenv("NB_PROXY_CROWDSEC_API_KEY", "crowdsec-key")
	t.Setenv("NB_PROXY_PREALLOCATED_BUFFERS", "1024")
	t.Setenv("NB_PROXY_MAX_BATCH_SIZE", "64")
	cmd := newLegacyProxyCommand(t)

	cfg, err := loadConfig(cmd, "")
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.LogLevel, "Legacy log-level environment binding should remain supported")
	assert.Equal(t, ":8443", cfg.ListenAddr, "Legacy address environment binding should remain supported")
	assert.Equal(t, "https://management.example.com:443", cfg.ManagementAddress,
		"Legacy management environment binding should remain supported")
	assert.Equal(t, "proxy.example.com", cfg.ProxyURL, "Legacy domain environment binding should remain supported")
	assert.Equal(t, "proxy-token", cfg.ProxyToken, "Legacy token environment binding should remain supported")
	assert.Equal(t, "/var/lib/proxy/certs", cfg.CertificateDirectory, "Legacy certificate directory should remain supported")
	assert.Equal(t, "proxy.crt", cfg.CertificateFile, "Legacy certificate file should remain supported")
	assert.Equal(t, "proxy.key", cfg.CertificateKeyFile, "Legacy certificate key should remain supported")
	assert.True(t, cfg.GenerateACMECertificates, "Legacy ACME toggle should remain supported")
	assert.Equal(t, ":8080", cfg.ACMEChallengeAddress, "Legacy ACME address should remain supported")
	assert.Equal(t, "https://acme.example.com/directory", cfg.ACMEDirectory, "Legacy ACME directory should remain supported")
	assert.Equal(t, "eab-kid", cfg.ACMEEABKID, "Legacy EAB KID should remain supported")
	assert.Equal(t, "eab-hmac", cfg.ACMEEABHMACKey, "Legacy EAB HMAC key should remain supported")
	assert.Equal(t, "http-01", cfg.ACMEChallengeType, "Legacy ACME challenge type should remain supported")
	assert.Equal(t, "flock", string(cfg.CertLockMethod), "Legacy certificate lock method should remain supported")
	assert.Equal(t, "/var/lib/proxy/wildcards", cfg.WildcardCertDir, "Legacy wildcard certificate directory should remain supported")
	assert.True(t, cfg.DebugEndpointEnabled, "Legacy debug endpoint toggle should remain supported")
	assert.Equal(t, "localhost:9444", cfg.DebugEndpointAddress, "Legacy debug endpoint address should remain supported")
	assert.Equal(t, "localhost:9080", cfg.HealthAddr, "Legacy health address should remain supported")
	assert.Equal(t, "https", cfg.ForwardedProto, "Legacy forwarded-proto environment binding should remain supported")
	require.NotNil(t, cfg.TrustedProxies, "Legacy trusted proxy environment binding should remain supported")
	assert.False(t, cfg.TrustedProxies.Empty(), "Legacy trusted proxy environment binding should remain populated")
	assert.Equal(t, uint16(51820), cfg.WireguardPort, "Legacy tunnel port should remain supported")
	assert.True(t, cfg.ProxyProtocol, "Legacy PROXY protocol toggle should remain supported")
	assert.Equal(t, "pre-shared-key", cfg.PreSharedKey, "Legacy pre-shared key should remain supported")
	assert.False(t, cfg.SupportsCustomPorts, "Legacy custom-port toggle should remain supported")
	assert.True(t, cfg.RequireSubdomain, "Legacy subdomain toggle should remain supported")
	assert.True(t, cfg.Private, "Legacy private toggle should remain supported")
	assert.Equal(t, 5*time.Second, cfg.MaxDialTimeout, "Legacy dial timeout should remain supported")
	assert.Equal(t, 10*time.Minute, cfg.MaxSessionIdleTimeout, "Legacy idle timeout should remain supported")
	assert.Equal(t, 30*time.Second, cfg.MappingBatchWatchdog, "Legacy mapping watchdog should remain supported")
	assert.Equal(t, "/var/lib/proxy/geo", cfg.GeoDataDir, "Legacy geodata directory should remain supported")
	assert.Equal(t, "https://crowdsec.example.com", cfg.CrowdSecAPIURL, "Legacy CrowdSec URL should remain supported")
	assert.Equal(t, "crowdsec-key", cfg.CrowdSecAPIKey, "Legacy CrowdSec key should remain supported")
	require.NotNil(t, cfg.PreallocatedBuffers, "Legacy preallocated buffer environment binding should remain supported")
	assert.Equal(t, uint32(1024), *cfg.PreallocatedBuffers, "Legacy preallocated buffer value should remain supported")
	require.NotNil(t, cfg.MaxBatchSize, "Legacy maximum batch environment binding should remain supported")
	assert.Equal(t, uint32(64), *cfg.MaxBatchSize, "Legacy maximum batch value should remain supported")
}

func TestLoadConfigPreservesLegacyInvalidEnvironmentBehavior(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		wantErr  bool
		validate func(*testing.T, *commandConfig)
	}{
		{
			name:    "invalid boolean uses default",
			envName: "NB_PROXY_SUPPORTS_CUSTOM_PORTS",
			value:   "invalid",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.True(t, cfg.SupportsCustomPorts, "Invalid legacy booleans should retain their default")
			},
		},
		{
			name:    "invalid uint16 uses default",
			envName: "NB_PROXY_WG_PORT",
			value:   "invalid",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.WireguardPort, "Invalid legacy uint16 values should retain their default")
			},
		},
		{
			name:    "invalid duration uses default",
			envName: "NB_PROXY_MAX_DIAL_TIMEOUT",
			value:   "invalid",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxDialTimeout, "Invalid legacy durations should retain their default")
			},
		},
		{
			name:    "invalid watchdog uses default",
			envName: "NB_PROXY_MAPPING_BATCH_WATCHDOG",
			value:   "invalid",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MappingBatchWatchdog, "Invalid legacy watchdog values should retain their default")
			},
		},
		{
			name:    "empty performance value remains absent",
			envName: "NB_PROXY_PREALLOCATED_BUFFERS",
			value:   "",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Nil(t, cfg.PreallocatedBuffers, "Empty legacy performance values should remain absent")
			},
		},
		{
			name:    "invalid performance value remains fatal",
			envName: "NB_PROXY_PREALLOCATED_BUFFERS",
			value:   "invalid",
			wantErr: true,
		},
		{
			name:    "empty maximum batch remains absent",
			envName: "NB_PROXY_MAX_BATCH_SIZE",
			value:   "",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Nil(t, cfg.MaxBatchSize, "Empty legacy maximum batch values should remain absent")
			},
		},
		{
			name:    "invalid maximum batch remains fatal",
			envName: "NB_PROXY_MAX_BATCH_SIZE",
			value:   "invalid",
			wantErr: true,
		},
		{
			name:    "empty string clears default",
			envName: "NB_PROXY_MANAGEMENT_ADDRESS",
			value:   "",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Empty(t, cfg.ManagementAddress, "Empty legacy strings should continue to clear their default")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv(test.envName, test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if test.wantErr {
				assert.Error(t, err, "Legacy-fatal environment input should remain fatal")
				return
			}
			if !assert.NoError(t, err, "Legacy fallback parsing should not abort Proxy startup") {
				return
			}
			test.validate(t, cfg)
		})
	}
}

func TestLegacyProxyFlagsRemainRegistered(t *testing.T) {
	for _, name := range []string{
		"mgmt",
		"addr",
		"domain",
		"cert-dir",
		"acme-certs",
		"acme-addr",
		"acme-dir",
		"acme-eab-kid",
		"acme-eab-hmac-key",
		"acme-challenge-type",
		"debug-endpoint",
		"debug-endpoint-addr",
		"health-addr",
		"forwarded-proto",
		"trusted-proxies",
		"cert-file",
		"cert-key-file",
		"cert-lock-method",
		"wildcard-cert-dir",
		"wg-port",
		"proxy-protocol",
		"preshared-key",
		"supports-custom-ports",
		"require-subdomain",
		"private",
		"max-dial-timeout",
		"max-session-idle-timeout",
		"geo-data-dir",
		"crowdsec-api-url",
		"crowdsec-api-key",
	} {
		assert.NotNil(t, rootCmd.Flags().Lookup(name), "Legacy flag %s should remain registered", name)
	}
	for _, name := range []string{"log-level", "debug"} {
		assert.NotNil(t, rootCmd.PersistentFlags().Lookup(name), "Legacy persistent flag %s should remain registered", name)
	}
}

func TestLoadConfigIgnoresEmptyBooleanEnvironment(t *testing.T) {
	clearProxyConfigEnvironment(t)
	t.Setenv("NB_PROXY_SUPPORTS_CUSTOM_PORTS", "")
	cmd := newLegacyProxyCommand(t)

	cfg, err := loadConfig(cmd, "")
	require.NoError(t, err)
	assert.True(t, cfg.SupportsCustomPorts,
		"An empty boolean environment variable should retain the previous default")
}

func TestDeprecatedDebugEnvironmentOverridesLogLevelFlag(t *testing.T) {
	clearProxyConfigEnvironment(t)
	t.Setenv("NB_PROXY_TOKEN", "test-token")
	t.Setenv("NB_PROXY_DOMAIN", "invalid domain")
	t.Setenv("NB_PROXY_DEBUG_LOGS", "true")
	cmd := newLegacyProxyCommand(t)

	logLevelFlag := cmd.Flags().Lookup("log-level")
	require.NotNil(t, logLevelFlag, "Log level flag should be registered")
	oldDebugLogs := debugLogs
	oldConfigPath := configPath
	t.Cleanup(func() {
		debugLogs = oldDebugLogs
		configPath = oldConfigPath
	})

	require.NoError(t, logLevelFlag.Value.Set("trace"))
	logLevelFlag.Changed = true
	debugLogs = envBoolOrDefault("NB_PROXY_DEBUG_LOGS", false)
	configPath = ""
	require.True(t, debugLogs, "Deprecated debug environment variable should be enabled")

	var runErr error
	output := captureStderr(t, func() {
		runErr = runServer(cmd, nil)
	})
	require.Error(t, runErr)
	assert.Contains(t, output, "configured log level: debug",
		"The deprecated debug environment variable should retain its previous precedence")
}

func TestLoadConfigPrecedence(t *testing.T) {
	clearProxyConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "proxy.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
domain: file.example.com
trustedProxies: 192.0.2.0/24
maxDialTimeout: 5s
`), 0o600))
	t.Setenv("NB_PROXY_TOKEN", "environment-token")
	cmd := newLegacyProxyCommand(t)

	domainFlag := cmd.Flags().Lookup("domain")
	require.NoError(t, domainFlag.Value.Set("flag.example.com"))
	domainFlag.Changed = true

	cfg, err := loadConfig(cmd, configPath)
	require.NoError(t, err)
	assert.Equal(t, "flag.example.com", cfg.ProxyURL, "Flags should override the configuration file")
	assert.Equal(t, "environment-token", cfg.ProxyToken, "Environment should populate secrets")
	assert.Equal(t, 5*time.Second, cfg.MaxDialTimeout, "Durations should be decoded from the file")
	require.NotNil(t, cfg.TrustedProxies, "Trusted proxies should be decoded")
	assert.False(t, cfg.TrustedProxies.Empty(), "Configured trusted proxies should not be empty")
}

// proxy-01: legacy read only the explicit NB_PROXY_* names; NB_<YAMLKEY> style
// variables were never consulted.
func TestLoadConfigIgnoresAutomaticEnvironmentAliases(t *testing.T) {
	tests := []struct {
		name     string
		alias    string
		value    string
		legacy   map[string]string
		validate func(*testing.T, *commandConfig)
	}{
		{
			name:   "listen address alias is ignored",
			alias:  "NB_LISTENADDRESS",
			value:  ":9999",
			legacy: map[string]string{"NB_PROXY_ADDRESS": ":8443"},
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Equal(t, ":8443", cfg.ListenAddr,
					"Legacy only read NB_PROXY_ADDRESS; NB_LISTENADDRESS must not override it")
			},
		},
		{
			name:   "log level alias is ignored",
			alias:  "NB_LOGLEVEL",
			value:  "trace",
			legacy: map[string]string{"NB_PROXY_LOG_LEVEL": "warn"},
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Equal(t, "warn", cfg.LogLevel,
					"Legacy only read NB_PROXY_LOG_LEVEL; NB_LOGLEVEL must not override it")
			},
		},
		{
			name:  "token alias is ignored",
			alias: "NB_PROXYTOKEN",
			value: "alias-token",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Empty(t, cfg.ProxyToken,
					"Legacy only read NB_PROXY_TOKEN; NB_PROXYTOKEN must not satisfy the token requirement")
			},
		},
		{
			name:  "private alias is ignored",
			alias: "NB_PRIVATE",
			value: "true",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.Private,
					"Legacy only read NB_PROXY_PRIVATE; NB_PRIVATE must not enable private mode")
			},
		},
		{
			name:  "id alias is ignored",
			alias: "NB_ID",
			value: "alias-id",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Empty(t, cfg.ID, "Legacy never read NB_ID; the proxy ID must stay empty")
			},
		},
		{
			name:   "management address alias is ignored",
			alias:  "NB_MANAGEMENTADDRESS",
			value:  "https://alias.example.com:443",
			legacy: map[string]string{"NB_PROXY_MANAGEMENT_ADDRESS": "https://management.example.com:443"},
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Equal(t, "https://management.example.com:443", cfg.ManagementAddress,
					"Legacy only read NB_PROXY_MANAGEMENT_ADDRESS; NB_MANAGEMENTADDRESS must not override it")
			},
		},
		{
			name:  "wireguard port alias is ignored",
			alias: "NB_WIREGUARDPORT",
			value: "51820",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.WireguardPort,
					"Legacy only read NB_PROXY_WG_PORT; NB_WIREGUARDPORT must not set the tunnel port")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			for name, value := range test.legacy {
				t.Setenv(name, value)
			}
			t.Setenv(test.alias, test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			require.NoError(t, err)
			test.validate(t, cfg)
		})
	}
}

// proxy-02: NB_DOMAIN is a common self-hosted variable; legacy ignored it and
// only honoured NB_PROXY_DOMAIN / --domain.
func TestLoadConfigIgnoresSharedDomainEnvironment(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "valid shared domain is ignored", domain: "netbird.example.org"},
		{name: "invalid shared domain is ignored", domain: "bad domain"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv("NB_PROXY_DOMAIN", "proxy.example.com")
			t.Setenv("NB_DOMAIN", test.domain)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			require.NoError(t, err)
			assert.Equal(t, "proxy.example.com", cfg.ProxyURL,
				"Legacy only read NB_PROXY_DOMAIN; the shared NB_DOMAIN variable must not override it")
		})
	}
}

// proxy-03: legacy had no NB_PROXY_ID binding; the ID was always generated at
// Server.Start time.
func TestLoadConfigIgnoresProxyIDEnvironment(t *testing.T) {
	clearProxyConfigEnvironment(t)
	t.Setenv("NB_PROXY_ID", "my-proxy")
	cmd := newLegacyProxyCommand(t)

	cfg, err := loadConfig(cmd, "")
	require.NoError(t, err)
	assert.Empty(t, cfg.ID,
		"Legacy never read NB_PROXY_ID; the proxy ID must stay empty so Server.Start generates it")
}

// proxy-04: legacy strconv.ParseBool rejected yes/no/on/off/y/n, logging a
// warning and keeping the flag default.
func TestLoadConfigPreservesLegacyBooleanVocabulary(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		validate func(*testing.T, *commandConfig)
	}{
		{
			name:    "no keeps custom ports enabled",
			envName: "NB_PROXY_SUPPORTS_CUSTOM_PORTS",
			value:   "no",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.True(t, cfg.SupportsCustomPorts, "Legacy ParseBool rejected \"no\" and kept the default true")
			},
		},
		{
			name:    "off keeps custom ports enabled",
			envName: "NB_PROXY_SUPPORTS_CUSTOM_PORTS",
			value:   "off",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.True(t, cfg.SupportsCustomPorts, "Legacy ParseBool rejected \"off\" and kept the default true")
			},
		},
		{
			name:    "n keeps custom ports enabled",
			envName: "NB_PROXY_SUPPORTS_CUSTOM_PORTS",
			value:   "n",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.True(t, cfg.SupportsCustomPorts, "Legacy ParseBool rejected \"n\" and kept the default true")
			},
		},
		{
			name:    "uppercase OFF keeps custom ports enabled",
			envName: "NB_PROXY_SUPPORTS_CUSTOM_PORTS",
			value:   "OFF",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.True(t, cfg.SupportsCustomPorts, "Legacy ParseBool rejected \"OFF\" and kept the default true")
			},
		},
		{
			name:    "yes keeps ACME disabled",
			envName: "NB_PROXY_ACME_CERTIFICATES",
			value:   "yes",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.GenerateACMECertificates, "Legacy ParseBool rejected \"yes\" and kept the default false")
			},
		},
		{
			name:    "uppercase ON keeps ACME disabled",
			envName: "NB_PROXY_ACME_CERTIFICATES",
			value:   "ON",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.GenerateACMECertificates, "Legacy ParseBool rejected \"ON\" and kept the default false")
			},
		},
		{
			name:    "y keeps ACME disabled",
			envName: "NB_PROXY_ACME_CERTIFICATES",
			value:   "y",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.GenerateACMECertificates, "Legacy ParseBool rejected \"y\" and kept the default false")
			},
		},
		{
			name:    "on keeps PROXY protocol disabled",
			envName: "NB_PROXY_PROXY_PROTOCOL",
			value:   "on",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.ProxyProtocol, "Legacy ParseBool rejected \"on\" and kept the default false")
			},
		},
		{
			name:    "Y keeps subdomain requirement disabled",
			envName: "NB_PROXY_REQUIRE_SUBDOMAIN",
			value:   "Y",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.RequireSubdomain, "Legacy ParseBool rejected \"Y\" and kept the default false")
			},
		},
		{
			name:    "on keeps private mode disabled",
			envName: "NB_PROXY_PRIVATE",
			value:   "on",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.False(t, cfg.Private, "Legacy ParseBool rejected \"on\" and kept the default false")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv(test.envName, test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if !assert.NoError(t, err, "Legacy boolean fallback parsing should not abort Proxy startup") {
				return
			}
			test.validate(t, cfg)
		})
	}
}

// proxy-05: legacy parsed NB_PROXY_WG_PORT with strconv.ParseUint(v, 10, 16).
func TestLoadConfigPreservesLegacyWireguardPortParsing(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  uint16
	}{
		{name: "leading zero is decimal", value: "010", want: 10},
		{name: "hex prefix falls back to default", value: "0x1F", want: 0},
		{name: "octal prefix falls back to default", value: "0o17", want: 0},
		{name: "underscore separator falls back to default", value: "1_000", want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv("NB_PROXY_WG_PORT", test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if !assert.NoError(t, err, "Legacy uint16 fallback parsing should not abort Proxy startup") {
				return
			}
			assert.Equal(t, test.want, cfg.WireguardPort,
				"Legacy parsed NB_PROXY_WG_PORT=%q in base 10 (parse errors fell back to 0)", test.value)
		})
	}
}

// proxy-07: legacy time.ParseDuration("") failed, logging a warning and
// keeping the default of 0; startup continued.
func TestLoadConfigPreservesLegacyEmptyDurationEnvironment(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		validate func(*testing.T, *commandConfig)
	}{
		{
			name:    "empty dial timeout uses default",
			envName: "NB_PROXY_MAX_DIAL_TIMEOUT",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxDialTimeout, "Legacy treated an empty dial timeout as the default 0")
			},
		},
		{
			name:    "empty idle timeout uses default",
			envName: "NB_PROXY_MAX_SESSION_IDLE_TIMEOUT",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxSessionIdleTimeout, "Legacy treated an empty idle timeout as the default 0")
			},
		},
		{
			name:    "empty watchdog uses default",
			envName: "NB_PROXY_MAPPING_BATCH_WATCHDOG",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MappingBatchWatchdog, "Legacy treated an empty watchdog as the default 0")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv(test.envName, "")
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if !assert.NoError(t, err, "Legacy treated an empty duration environment value as a warning, not a fatal error") {
				return
			}
			test.validate(t, cfg)
		})
	}
}

// proxy-08: legacy time.ParseDuration errors (missing unit / invalid) logged a
// warning and kept the default of 0; startup continued.
func TestLoadConfigPreservesLegacyDurationFallbacks(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		validate func(*testing.T, *commandConfig)
	}{
		{
			name:    "unit-less dial timeout uses default",
			envName: "NB_PROXY_MAX_DIAL_TIMEOUT",
			value:   "5",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxDialTimeout, "Legacy treated a unit-less dial timeout as the default 0")
			},
		},
		{
			name:    "unit-less idle timeout uses default",
			envName: "NB_PROXY_MAX_SESSION_IDLE_TIMEOUT",
			value:   "5",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxSessionIdleTimeout, "Legacy treated a unit-less idle timeout as the default 0")
			},
		},
		{
			name:    "invalid idle timeout uses default",
			envName: "NB_PROXY_MAX_SESSION_IDLE_TIMEOUT",
			value:   "invalid",
			validate: func(t *testing.T, cfg *commandConfig) {
				assert.Zero(t, cfg.MaxSessionIdleTimeout, "Legacy treated an invalid idle timeout as the default 0")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv(test.envName, test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if !assert.NoError(t, err, "Legacy treated an unparseable duration environment value as a warning, not a fatal error") {
				return
			}
			test.validate(t, cfg)
		})
	}
}

// proxy-09: legacy parsed the performance variables with
// strconv.ParseUint(raw, 10, 32) and aborted startup on any parse error.
func TestLoadConfigPreservesLegacyPerformanceParsing(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		value   string
		want    uint32
		wantErr bool
	}{
		{name: "preallocated buffers leading zero is decimal", envName: "NB_PROXY_PREALLOCATED_BUFFERS", value: "010", want: 10},
		{name: "preallocated buffers two leading zeros is decimal", envName: "NB_PROXY_PREALLOCATED_BUFFERS", value: "0100", want: 100},
		{name: "preallocated buffers hex remains fatal", envName: "NB_PROXY_PREALLOCATED_BUFFERS", value: "0x10", wantErr: true},
		{name: "preallocated buffers long hex remains fatal", envName: "NB_PROXY_PREALLOCATED_BUFFERS", value: "0x100", wantErr: true},
		{name: "preallocated buffers underscore remains fatal", envName: "NB_PROXY_PREALLOCATED_BUFFERS", value: "1_000", wantErr: true},
		{name: "maximum batch leading zero is decimal", envName: "NB_PROXY_MAX_BATCH_SIZE", value: "010", want: 10},
		{name: "maximum batch two leading zeros is decimal", envName: "NB_PROXY_MAX_BATCH_SIZE", value: "0100", want: 100},
		{name: "maximum batch hex remains fatal", envName: "NB_PROXY_MAX_BATCH_SIZE", value: "0x10", wantErr: true},
		{name: "maximum batch long hex remains fatal", envName: "NB_PROXY_MAX_BATCH_SIZE", value: "0x100", wantErr: true},
		{name: "maximum batch underscore remains fatal", envName: "NB_PROXY_MAX_BATCH_SIZE", value: "1_000", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			t.Setenv(test.envName, test.value)
			cmd := newLegacyProxyCommand(t)

			cfg, err := loadConfig(cmd, "")
			if test.wantErr {
				assert.Error(t, err,
					"Legacy strconv.ParseUint(%q, 10, 32) failed and aborted Proxy startup", test.value)
				return
			}
			if !assert.NoError(t, err, "Legacy base-10 performance values should not abort Proxy startup") {
				return
			}
			got := cfg.PreallocatedBuffers
			if test.envName == "NB_PROXY_MAX_BATCH_SIZE" {
				got = cfg.MaxBatchSize
			}
			require.NotNil(t, got, "Legacy performance values should be present when set")
			assert.Equal(t, test.want, *got,
				"Legacy parsed %s=%q in base 10", test.envName, test.value)
		})
	}
}

// proxy-10 / proxy-12: legacy read the token only from NB_PROXY_TOKEN, checked
// it before anything else, and reported a fixed message when it was missing.
func TestRunServerPreservesLegacyTokenRequirement(t *testing.T) {
	const legacyTokenError = "proxy token is required: set NB_PROXY_TOKEN environment variable"

	tests := []struct {
		name       string
		env        map[string]string
		fileConfig string
	}{
		{
			name: "missing token without other sources",
		},
		{
			name:       "file token does not satisfy the requirement",
			fileConfig: "proxyToken: file-token\ndomain: \"invalid domain\"\n",
		},
		{
			name: "token alias does not satisfy the requirement",
			env:  map[string]string{"NB_PROXYTOKEN": "alias-token", "NB_PROXY_DOMAIN": "invalid domain"},
		},
		{
			name:       "empty token with file token remains fatal",
			env:        map[string]string{"NB_PROXY_TOKEN": ""},
			fileConfig: "proxyToken: file-token\ndomain: \"invalid domain\"\n",
		},
		{
			name: "missing token is reported before performance parsing",
			env:  map[string]string{"NB_PROXY_PREALLOCATED_BUFFERS": "invalid"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			cmd := newLegacyProxyCommand(t)

			oldDebugLogs := debugLogs
			oldConfigPath := configPath
			t.Cleanup(func() {
				debugLogs = oldDebugLogs
				configPath = oldConfigPath
			})
			debugLogs = false
			configPath = ""
			if test.fileConfig != "" {
				configPath = filepath.Join(t.TempDir(), "proxy.yaml")
				require.NoError(t, os.WriteFile(configPath, []byte(test.fileConfig), 0o600))
			}

			var runErr error
			captureStderr(t, func() {
				runErr = runServer(cmd, nil)
			})
			require.Error(t, runErr)
			assert.EqualError(t, runErr, legacyTokenError,
				"Legacy accepted the token only from NB_PROXY_TOKEN and reported it before any other startup step")
		})
	}
}

func newLegacyProxyCommand(t *testing.T) *cobra.Command {
	t.Helper()

	defaults := legacyProxyDefaults(t)
	cmd := &cobra.Command{Use: "proxy-test"}
	flags := cmd.Flags()
	flags.String("log-level", defaults.LogLevel, "")
	flags.Bool("debug", false, "")
	flags.String("mgmt", defaults.ManagementAddress, "")
	flags.String("addr", defaults.ListenAddr, "")
	flags.String("domain", defaults.ProxyURL, "")
	flags.String("cert-dir", defaults.CertificateDirectory, "")
	flags.Bool("acme-certs", defaults.GenerateACMECertificates, "")
	flags.String("acme-addr", defaults.ACMEChallengeAddress, "")
	flags.String("acme-dir", defaults.ACMEDirectory, "")
	flags.String("acme-eab-kid", defaults.ACMEEABKID, "")
	flags.String("acme-eab-hmac-key", defaults.ACMEEABHMACKey, "")
	flags.String("acme-challenge-type", defaults.ACMEChallengeType, "")
	flags.Bool("debug-endpoint", defaults.DebugEndpointEnabled, "")
	flags.String("debug-endpoint-addr", defaults.DebugEndpointAddress, "")
	flags.String("health-addr", defaults.HealthAddr, "")
	flags.String("forwarded-proto", defaults.ForwardedProto, "")
	flags.String("trusted-proxies", "", "")
	flags.String("cert-file", defaults.CertificateFile, "")
	flags.String("cert-key-file", defaults.CertificateKeyFile, "")
	flags.String("cert-lock-method", string(defaults.CertLockMethod), "")
	flags.String("wildcard-cert-dir", defaults.WildcardCertDir, "")
	flags.Uint16("wg-port", defaults.WireguardPort, "")
	flags.Bool("proxy-protocol", defaults.ProxyProtocol, "")
	flags.String("preshared-key", defaults.PreSharedKey, "")
	flags.Bool("supports-custom-ports", defaults.SupportsCustomPorts, "")
	flags.Bool("require-subdomain", defaults.RequireSubdomain, "")
	flags.Bool("private", defaults.Private, "")
	flags.Duration("max-dial-timeout", defaults.MaxDialTimeout, "")
	flags.Duration("max-session-idle-timeout", defaults.MaxSessionIdleTimeout, "")
	flags.String("geo-data-dir", defaults.GeoDataDir, "")
	flags.String("crowdsec-api-url", defaults.CrowdSecAPIURL, "")
	flags.String("crowdsec-api-key", defaults.CrowdSecAPIKey, "")
	return cmd
}

func legacyProxyDefaults(t *testing.T) *commandConfig {
	t.Helper()

	trustedProxies, err := trustedproxy.Parse("")
	require.NoError(t, err)
	cfg := &commandConfig{LogLevel: "info"}
	cfg.ListenAddr = ":443"
	cfg.ManagementAddress = DefaultManagementURL
	cfg.CertificateDirectory = "./certs"
	cfg.CertificateFile = "tls.crt"
	cfg.CertificateKeyFile = "tls.key"
	cfg.ACMEChallengeAddress = ":80"
	cfg.ACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	cfg.ACMEChallengeType = "tls-alpn-01"
	cfg.CertLockMethod = "auto"
	cfg.DebugEndpointAddress = "localhost:8444"
	cfg.HealthAddr = "localhost:8080"
	cfg.ForwardedProto = "auto"
	cfg.TrustedProxies = trustedProxies
	cfg.SupportsCustomPorts = true
	cfg.GeoDataDir = "/var/lib/netbird/geolocation"
	return cfg
}

func clearProxyConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"NB_PROXY_LOG_LEVEL",
		"NB_PROXY_DEBUG_LOGS",
		"NB_PROXY_MANAGEMENT_ADDRESS",
		"NB_PROXY_ADDRESS",
		"NB_PROXY_DOMAIN",
		"NB_PROXY_TOKEN",
		"NB_PROXY_CERTIFICATE_DIRECTORY",
		"NB_PROXY_CERTIFICATE_FILE",
		"NB_PROXY_CERTIFICATE_KEY_FILE",
		"NB_PROXY_ACME_CERTIFICATES",
		"NB_PROXY_ACME_ADDRESS",
		"NB_PROXY_ACME_DIRECTORY",
		"NB_PROXY_ACME_EAB_KID",
		"NB_PROXY_ACME_EAB_HMAC_KEY",
		"NB_PROXY_ACME_CHALLENGE_TYPE",
		"NB_PROXY_CERT_LOCK_METHOD",
		"NB_PROXY_WILDCARD_CERT_DIR",
		"NB_PROXY_DEBUG_ENDPOINT",
		"NB_PROXY_DEBUG_ENDPOINT_ADDRESS",
		"NB_PROXY_HEALTH_ADDRESS",
		"NB_PROXY_FORWARDED_PROTO",
		"NB_PROXY_TRUSTED_PROXIES",
		"NB_PROXY_WG_PORT",
		"NB_PROXY_PROXY_PROTOCOL",
		"NB_PROXY_PRESHARED_KEY",
		"NB_PROXY_SUPPORTS_CUSTOM_PORTS",
		"NB_PROXY_REQUIRE_SUBDOMAIN",
		"NB_PROXY_PRIVATE",
		"NB_PROXY_MAX_DIAL_TIMEOUT",
		"NB_PROXY_MAX_SESSION_IDLE_TIMEOUT",
		"NB_PROXY_MAPPING_BATCH_WATCHDOG",
		"NB_PROXY_GEO_DATA_DIR",
		"NB_PROXY_CROWDSEC_API_URL",
		"NB_PROXY_CROWDSEC_API_KEY",
		"NB_PROXY_PREALLOCATED_BUFFERS",
		"NB_PROXY_MAX_BATCH_SIZE",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	oldStderr := os.Stderr
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	os.Stderr = oldStderr
	require.NoError(t, writer.Close())

	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	return string(output)
}
