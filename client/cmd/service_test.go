package cmd

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain intercepts when this test binary is run as a daemon subprocess.
// On FreeBSD, the rc.d service script runs the binary via daemon(8) -r with
// "service run ..." arguments. Since the test binary can't handle cobra CLI
// args, it exits immediately, causing daemon -r to respawn rapidly until
// hitting the rate limit and exiting. This makes service restart unreliable.
// Blocking here keeps the subprocess alive until the init system sends SIGTERM.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "service" && os.Args[2] == "run" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
		<-sig
		return
	}
	os.Exit(m.Run())
}

// TestServiceEnvVars tests environment variable parsing
func TestServiceEnvVars(t *testing.T) {
	tests := []struct {
		name      string
		envVars   []string
		expected  map[string]string
		expectErr bool
	}{
		{
			name:    "Valid single env var",
			envVars: []string{"LOG_LEVEL=debug"},
			expected: map[string]string{
				"LOG_LEVEL": "debug",
			},
		},
		{
			name:    "Valid multiple env vars",
			envVars: []string{"LOG_LEVEL=debug", "CUSTOM_VAR=value"},
			expected: map[string]string{
				"LOG_LEVEL":  "debug",
				"CUSTOM_VAR": "value",
			},
		},
		{
			name:    "Env var with spaces",
			envVars: []string{" KEY = value "},
			expected: map[string]string{
				"KEY": "value",
			},
		},
		{
			name:      "Invalid format - no equals",
			envVars:   []string{"INVALID"},
			expectErr: true,
		},
		{
			name:      "Invalid format - empty key",
			envVars:   []string{"=value"},
			expectErr: true,
		},
		{
			name:    "Empty value is valid",
			envVars: []string{"KEY="},
			expected: map[string]string{
				"KEY": "",
			},
		},
		{
			name:     "Empty slice",
			envVars:  []string{},
			expected: map[string]string{},
		},
		{
			name:     "Empty string in slice",
			envVars:  []string{"", "KEY=value", ""},
			expected: map[string]string{"KEY": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseServiceEnvVars(tt.envVars)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestServiceConfigWithEnvVars tests service config creation with env vars
func TestServiceConfigWithEnvVars(t *testing.T) {
	originalServiceName := serviceName
	originalServiceEnvVars := serviceEnvVars
	defer func() {
		serviceName = originalServiceName
		serviceEnvVars = originalServiceEnvVars
	}()

	serviceName = "test-service"
	serviceEnvVars = []string{"TEST_VAR=test_value", "ANOTHER_VAR=another_value"}

	cfg, err := newSVCConfig()
	require.NoError(t, err)

	assert.Equal(t, "test-service", cfg.Name)
	assert.Equal(t, "test_value", cfg.EnvVars["TEST_VAR"])
	assert.Equal(t, "another_value", cfg.EnvVars["ANOTHER_VAR"])

	if runtime.GOOS == "linux" {
		assert.Equal(t, "test-service", cfg.EnvVars["SYSTEMD_UNIT"])
	}
}
