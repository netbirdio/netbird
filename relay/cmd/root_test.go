package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsPortFlag(t *testing.T) {
	flags := rootCmd.PersistentFlags()
	flag := flags.Lookup("metrics-port")
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		require.NoError(t, flags.Set(flag.Name, previous))
		flag.Changed = changed
	})

	assert.Equal(t, "9090", flag.DefValue, "default metrics port must remain unchanged")
	for _, tc := range []struct{ value, address string }{
		{"9091", ":9091"},
		{"0", ":0"},
		{"0x2382", ":9090"},
		{"021602", ":9090"},
		{"+9090", ":9090"},
		{":9090", ":9090"},
		{"127.0.0.1:9090", "127.0.0.1:9090"},
		{"[::1]:9090", "[::1]:9090"},
		{"localhost:9090", "localhost:9090"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			require.NoError(t, flags.Set(flag.Name, tc.value))
			address, err := cobraConfig.metricsListenAddress()
			require.NoError(t, err)
			assert.Equal(t, tc.address, address, "metrics must preserve the requested bind address")
		})
	}
}

func TestMetricsPortEnvironment(t *testing.T) {
	flags := rootCmd.PersistentFlags()
	flag := flags.Lookup("metrics-port")
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		require.NoError(t, flags.Set(flag.Name, previous))
		flag.Changed = changed
	})

	for _, value := range []string{"9091", "127.0.0.1:9090", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("NB_METRICS_PORT", value)
			setFlagsFromEnvVars(rootCmd)
			assert.Equal(t, value, cobraConfig.MetricsPort, "environment values must reach validation without falling back to a wildcard")
		})
	}
}

func TestConfigRejectsInvalidMetricsAddress(t *testing.T) {
	for _, value := range []string{"", "invalid", "-1", "65536", "127.0.0.1", "127.0.0.1:", "127.0.0.1:-1", "127.0.0.1:65536", "::1:9090"} {
		t.Run(value, func(t *testing.T) {
			cfg := Config{ExposedAddress: "relay.example.com:443", AuthSecret: "test-secret", MetricsPort: value}
			assert.Error(t, cfg.Validate(), "invalid metrics addresses must fail before starting listeners")
		})
	}
}
