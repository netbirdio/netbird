package cmd

import (
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleConfig(t *testing.T) {
	clearSignalConfigEnvironment(t)
	require.NoError(t, runCmd.ParseFlags(nil))
	cfg, err := loadConfig(runCmd, filepath.Join("..", "config.example.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/netbird/tls.crt", cfg.CertFile, "Example config should load")
}

func TestLoadConfigPreservesLegacyDefaults(t *testing.T) {
	clearSignalConfigEnvironment(t)
	require.NoError(t, runCmd.ParseFlags(nil))

	cfg, err := loadConfig(runCmd, "")
	require.NoError(t, err)
	assert.Equal(t, defaultConfig(), cfg, "Signal defaults should remain unchanged")
}

func TestLoadConfigPreservesLegacyEnvironmentBindings(t *testing.T) {
	clearSignalConfigEnvironment(t)
	t.Setenv("NB_PORT", "10001")
	t.Setenv("NB_LETSENCRYPT_DOMAIN", "signal.example.com")
	t.Setenv("NB_LETSENCRYPT_EMAIL", "admin@example.com")
	t.Setenv("NB_LETSENCRYPT_DATA_DIR", "/var/lib/signal/certs")
	t.Setenv("NB_CERT_FILE", "/etc/signal/tls.crt")
	t.Setenv("NB_CERT_KEY", "/etc/signal/tls.key")
	t.Setenv("NB_PPROF_ADDR", "localhost:6060")
	require.NoError(t, runCmd.ParseFlags(nil))

	cfg, err := loadConfig(runCmd, "")
	require.NoError(t, err)
	assert.Equal(t, &Config{
		Port:               10001,
		MetricsPort:        9090,
		LetsencryptDomain:  "signal.example.com",
		LetsencryptEmail:   "admin@example.com",
		LetsencryptDataDir: "/var/lib/signal/certs",
		CertFile:           "/etc/signal/tls.crt",
		CertKey:            "/etc/signal/tls.key",
		LogLevel:           "info",
		LogFile:            defaultConfig().LogFile,
		PprofAddress:       "localhost:6060",
	}, cfg, "Every legacy Signal environment binding should remain supported")
}

func TestLoadConfigIgnoresPreviouslyUnboundEmptyEnvironment(t *testing.T) {
	clearSignalConfigEnvironment(t)
	t.Setenv("NB_METRICS_PORT", "")
	require.NoError(t, runCmd.ParseFlags(nil))

	cfg, err := loadConfig(runCmd, "")
	require.NoError(t, err)
	assert.Equal(t, defaultConfig().MetricsPort, cfg.MetricsPort,
		"An environment variable that was previously unbound should not alter the default when empty")
}

func TestLoadConfigPreservesLegacyEnvironmentAliasPrecedence(t *testing.T) {
	clearSignalConfigEnvironment(t)
	t.Setenv("NB_LETSENCRYPT_DATA_DIR", "/preferred-certs")
	t.Setenv("NB_SSL_DIR", "/legacy-certs")
	require.NoError(t, runCmd.ParseFlags(nil))

	cfg, err := loadConfig(runCmd, "")
	require.NoError(t, err)
	assert.Equal(t, "/legacy-certs", cfg.LetsencryptDataDir,
		"The legacy alias should retain its previous precedence when both variables are set")
}

func TestSignalPortDefaultsRemainCompatible(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected int
	}{
		{name: "no TLS", expected: 80},
		{name: "letsencrypt", env: map[string]string{"NB_LETSENCRYPT_DOMAIN": "signal.example.com"}, expected: 443},
		{name: "certificate pair", env: map[string]string{"NB_CERT_FILE": "/tls.crt", "NB_CERT_KEY": "/tls.key"}, expected: 443},
		{name: "explicit nonzero port", env: map[string]string{"NB_PORT": "10002"}, expected: 10002},
		{name: "explicit zero port", env: map[string]string{"NB_PORT": "0"}, expected: 0},
		{name: "invalid port falls back", env: map[string]string{"NB_PORT": "invalid"}, expected: 80},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := runSignalPreRun(t, test.env)
			assert.Equal(t, test.expected, actual, "Signal implicit port selection should retain legacy behavior")
		})
	}
}

func TestSignalFlagAliasesRetainArgumentOrder(t *testing.T) {
	tests := []struct {
		name     string
		first    string
		second   string
		expected string
	}{
		{
			name:     "legacy alias last",
			first:    "letsencrypt-data-dir",
			second:   "ssl-dir",
			expected: "/ssl-dir",
		},
		{
			name:     "preferred alias last",
			first:    "ssl-dir",
			second:   "letsencrypt-data-dir",
			expected: "/letsencrypt-data-dir",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			require.NoError(t, runCmd.ParseFlags(nil))
			firstFlag := runCmd.PersistentFlags().Lookup(test.first)
			secondFlag := runCmd.PersistentFlags().Lookup(test.second)
			require.NotNil(t, firstFlag, "First alias should be registered")
			require.NotNil(t, secondFlag, "Second alias should be registered")
			oldDataDir := signalLetsencryptDataDir
			oldFirstValue, oldFirstChanged := firstFlag.Value.String(), firstFlag.Changed
			oldSecondValue, oldSecondChanged := secondFlag.Value.String(), secondFlag.Changed
			t.Cleanup(func() {
				require.NoError(t, firstFlag.Value.Set(oldFirstValue))
				firstFlag.Changed = oldFirstChanged
				require.NoError(t, secondFlag.Value.Set(oldSecondValue))
				secondFlag.Changed = oldSecondChanged
				signalLetsencryptDataDir = oldDataDir
			})

			require.NoError(t, firstFlag.Value.Set("/"+test.first))
			firstFlag.Changed = true
			require.NoError(t, secondFlag.Value.Set("/"+test.second))
			secondFlag.Changed = true

			cfg, err := loadConfig(runCmd, "")
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.LetsencryptDataDir,
				"When both CLI aliases are supplied, the last value should retain precedence")
		})
	}
}

func TestLegacySignalFlagsRemainRegistered(t *testing.T) {
	for _, name := range []string{
		"port",
		"letsencrypt-data-dir",
		"ssl-dir",
		"letsencrypt-domain",
		"letsencrypt-email",
		"cert-file",
		"cert-key",
	} {
		flag := runCmd.PersistentFlags().Lookup(name)
		require.NotNil(t, flag, "Legacy persistent flag %s should remain registered", name)
		assert.Empty(t, flag.Shorthand, "Legacy Signal flag %s should remain without a shorthand", name)
	}
	metricsFlag := runCmd.Flags().Lookup("metrics-port")
	require.NotNil(t, metricsFlag, "Legacy metrics flag should remain registered")
	assert.Empty(t, metricsFlag.Shorthand, "Legacy metrics flag should remain without a shorthand")
	for _, name := range []string{"log-level", "log-file"} {
		flag := rootCmd.PersistentFlags().Lookup(name)
		require.NotNil(t, flag, "Legacy root flag %s should remain registered", name)
		assert.Empty(t, flag.Shorthand, "Legacy Signal flag %s should remain without a shorthand", name)
	}
}

func runSignalPreRun(t *testing.T, environment map[string]string) int {
	t.Helper()

	clearSignalConfigEnvironment(t)
	for name, value := range environment {
		t.Setenv(name, value)
	}
	t.Setenv("NB_LOG_FILE", "console")
	require.NoError(t, runCmd.ParseFlags(nil))
	require.NoError(t, executeSignalPreRun(t, "0", false))
	return signalPort
}

// executeSignalPreRun snapshots the Signal runtime globals, the port flag and the standard logger,
// forces the port flag into the requested state, runs runCmd.PreRunE against the current
// environment and returns its error. Callers prepare the environment and call ParseFlags first.
func executeSignalPreRun(t *testing.T, portValue string, portChanged bool) error {
	t.Helper()

	oldSignalPort := signalPort
	oldMetricsPort := metricsPort
	oldLetsencryptDomain := signalLetsencryptDomain
	oldLetsencryptEmail := signalLetsencryptEmail
	oldLetsencryptDataDir := signalLetsencryptDataDir
	oldCertFile := signalCertFile
	oldCertKey := signalCertKey
	oldLogLevel := logLevel
	oldLogFile := logFile
	oldPprofAddress := signalPprofAddress
	oldConfigPath := signalConfigPath
	portFlag := runCmd.PersistentFlags().Lookup("port")
	require.NotNil(t, portFlag, "Signal port flag should be registered")
	oldPortValue := portFlag.Value.String()
	oldPortChanged := portFlag.Changed
	logger := log.StandardLogger()
	oldLoggerLevel, oldLoggerOut, oldLoggerFormatter := logger.GetLevel(), logger.Out, logger.Formatter
	t.Cleanup(func() {
		logger.SetLevel(oldLoggerLevel)
		logger.SetOutput(oldLoggerOut)
		logger.SetFormatter(oldLoggerFormatter)
		require.NoError(t, portFlag.Value.Set(oldPortValue))
		portFlag.Changed = oldPortChanged
		signalPort = oldSignalPort
		metricsPort = oldMetricsPort
		signalLetsencryptDomain = oldLetsencryptDomain
		signalLetsencryptEmail = oldLetsencryptEmail
		signalLetsencryptDataDir = oldLetsencryptDataDir
		signalCertFile = oldCertFile
		signalCertKey = oldCertKey
		logLevel = oldLogLevel
		logFile = oldLogFile
		signalPprofAddress = oldPprofAddress
		signalConfigPath = oldConfigPath
	})

	signalConfigPath = ""
	require.NoError(t, portFlag.Value.Set(portValue))
	portFlag.Changed = portChanged
	return runCmd.PreRunE(runCmd, nil)
}

func clearSignalConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"NB_PORT",
		"NB_METRICS_PORT",
		"NB_LETSENCRYPT_DOMAIN",
		"NB_LETSENCRYPT_EMAIL",
		"NB_LETSENCRYPT_DATA_DIR",
		"NB_SSL_DIR",
		"NB_CERT_FILE",
		"NB_CERT_KEY",
		"NB_LOG_LEVEL",
		"NB_LOG_FILE",
		"NB_PPROF_ADDR",
		// Collapsed camelCase spellings that the shared loader derives automatically; they never
		// existed in the legacy NB_<FLAG_NAME> mapping, so the suite must not inherit them either.
		"NB_METRICSPORT",
		"NB_LETSENCRYPTDOMAIN",
		"NB_LETSENCRYPTEMAIL",
		"NB_LETSENCRYPTDATADIR",
		"NB_CERTFILE",
		"NB_CERTKEY",
		"NB_LOGLEVEL",
		"NB_LOGFILE",
		"NB_PPROFADDRESS",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

func TestLoadConfigIgnoresPreviouslyUnboundMetricsPortEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "valid value", value: "9191"},
		{name: "invalid value", value: "abc"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			t.Setenv("NB_METRICS_PORT", test.value)
			require.NoError(t, runCmd.ParseFlags(nil))

			cfg, err := loadConfig(runCmd, "")
			assert.NoError(t, err,
				"metrics-port was a non-persistent flag that the legacy NB_ mapping never visited, so NB_METRICS_PORT could not fail startup")
			if err != nil {
				return
			}
			assert.Equal(t, defaultConfig().MetricsPort, cfg.MetricsPort,
				"metrics-port was a non-persistent flag that the legacy NB_ mapping never visited, so NB_METRICS_PORT must not move the metrics endpoint")
		})
	}
}

func TestLoadConfigPreservesLegacyEnvironmentAliasPrecedenceWithEmptyValues(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected string
	}{
		{
			name:     "empty preferred alias keeps legacy alias",
			env:      map[string]string{"NB_LETSENCRYPT_DATA_DIR": "", "NB_SSL_DIR": "/legacy-certs"},
			expected: "/legacy-certs",
		},
		{
			name:     "empty legacy alias clears preferred alias",
			env:      map[string]string{"NB_LETSENCRYPT_DATA_DIR": "/preferred-certs", "NB_SSL_DIR": ""},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			require.NoError(t, runCmd.ParseFlags(nil))

			cfg, err := loadConfig(runCmd, "")
			require.NoError(t, err)
			assert.Equal(t, test.expected, cfg.LetsencryptDataDir,
				"Legacy applied every present NB_ variable in flag order (letsencrypt-data-dir, then ssl-dir) into the same variable, so the last present alias won even when it was empty")
		})
	}
}

func TestLoadConfigIgnoresPreviouslyUnboundLogEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string
		field string
	}{
		{name: "valid log level", env: map[string]string{"NB_LOG_LEVEL": "debug"}},
		{name: "invalid log level", env: map[string]string{"NB_LOG_LEVEL": "verbose"}},
		{name: "empty log level", env: map[string]string{"NB_LOG_LEVEL": ""}},
		{name: "console log file", env: map[string]string{"NB_LOG_FILE": "console"}},
		{name: "syslog log file", env: map[string]string{"NB_LOG_FILE": "syslog"}},
		{name: "writable log file", env: map[string]string{"NB_LOG_FILE": filepath.Join(t.TempDir(), "signal.log")}},
		{name: "unwritable log file", env: map[string]string{"NB_LOG_FILE": filepath.Join(t.TempDir(), "missing", "dir", "signal.log")}},
		{name: "empty log file", env: map[string]string{"NB_LOG_FILE": ""}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			require.NoError(t, runCmd.ParseFlags(nil))

			cfg, err := loadConfig(runCmd, "")
			require.NoError(t, err)
			assert.Equal(t, defaultConfig().LogLevel, cfg.LogLevel,
				"log-level lived on the root command; the legacy NB_ mapping only visited run persistent flags, so NB_LOG_LEVEL was ignored and the level stayed info")
			assert.Equal(t, defaultConfig().LogFile, cfg.LogFile,
				"log-file lived on the root command; the legacy NB_ mapping only visited run persistent flags, so NB_LOG_FILE was ignored and logs went to the default file")
		})
	}
}

func TestSignalPreRunIgnoresPreviouslyUnboundLogLevelEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "valid log level", value: "debug"},
		{name: "invalid log level", value: "verbose"},
		{name: "empty log level", value: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			t.Setenv("NB_LOG_LEVEL", test.value)
			t.Setenv("NB_LOG_FILE", "console")
			require.NoError(t, runCmd.ParseFlags(nil))

			err := executeSignalPreRun(t, "0", false)
			assert.NoError(t, err,
				"NB_LOG_LEVEL was never applied by the legacy NB_ mapping, so any value left the service starting at level info")
			assert.Equal(t, "info", logLevel,
				"NB_LOG_LEVEL was never applied by the legacy NB_ mapping, so the effective level must remain info")
			if err == nil {
				assert.Equal(t, log.InfoLevel, log.StandardLogger().GetLevel(),
					"Legacy initialized the logger with the flag-only level info regardless of NB_LOG_LEVEL")
			}
		})
	}
}

func TestLoadConfigIgnoresCollapsedEnvironmentNames(t *testing.T) {
	clearSignalConfigEnvironment(t)
	t.Setenv("NB_METRICSPORT", "1234")
	t.Setenv("NB_LETSENCRYPTDOMAIN", "auto.example.com")
	t.Setenv("NB_LETSENCRYPTEMAIL", "auto@example.com")
	t.Setenv("NB_LETSENCRYPTDATADIR", "/auto-certs")
	t.Setenv("NB_CERTFILE", "/auto/tls.crt")
	t.Setenv("NB_CERTKEY", "/auto/tls.key")
	t.Setenv("NB_LOGLEVEL", "trace")
	t.Setenv("NB_LOGFILE", "console")
	t.Setenv("NB_PPROFADDRESS", "localhost:1")
	require.NoError(t, runCmd.ParseFlags(nil))

	cfg, err := loadConfig(runCmd, "")
	require.NoError(t, err)
	assert.Equal(t, defaultConfig(), cfg,
		"Legacy only mapped NB_<FLAG_NAME> with underscores between words; collapsed camelCase spellings such as NB_METRICSPORT did not exist and were ignored")
}

func TestLoadConfigPreservesDocumentedEnvironmentNamesOverCollapsedNames(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		actual   func(*Config) any
		expected any
	}{
		{
			name:     "pprof address",
			env:      map[string]string{"NB_PPROFADDRESS": "auto:2", "NB_PPROF_ADDR": "explicit:1"},
			actual:   func(cfg *Config) any { return cfg.PprofAddress },
			expected: "explicit:1",
		},
		{
			name:     "metrics port",
			env:      map[string]string{"NB_METRICSPORT": "7777", "NB_METRICS_PORT": "8888"},
			actual:   func(cfg *Config) any { return cfg.MetricsPort },
			expected: defaultConfig().MetricsPort,
		},
		{
			name:     "letsencrypt data dir",
			env:      map[string]string{"NB_LETSENCRYPTDATADIR": "/auto-certs", "NB_LETSENCRYPT_DATA_DIR": "/preferred-certs", "NB_SSL_DIR": "/legacy-certs"},
			actual:   func(cfg *Config) any { return cfg.LetsencryptDataDir },
			expected: "/legacy-certs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			require.NoError(t, runCmd.ParseFlags(nil))

			cfg, err := loadConfig(runCmd, "")
			require.NoError(t, err)
			assert.Equal(t, test.expected, test.actual(cfg),
				"Legacy read only the documented NB_ names (NB_PPROF_ADDR directly, NB_<FLAG_NAME> for persistent flags); an undocumented collapsed spelling must not override them")
		})
	}
}

func TestSignalExplicitZeroPortFlagRemainsCompatible(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "no TLS"},
		{name: "letsencrypt", env: map[string]string{"NB_LETSENCRYPT_DOMAIN": "signal.example.com"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSignalConfigEnvironment(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			t.Setenv("NB_LOG_FILE", "console")
			require.NoError(t, runCmd.ParseFlags(nil))

			require.NoError(t, executeSignalPreRun(t, "0", true))
			assert.Equal(t, 0, signalPort,
				"Legacy skipped the 80/443 default heuristic whenever the port flag was Changed, so `--port 0` kept 0 and bound an ephemeral port")
		})
	}
}
