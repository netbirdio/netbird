package profiling

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartSkipsSecondProfilerInProcess(t *testing.T) {
	clearEnv(t)
	t.Setenv("NB_PYROSCOPE_ADDRESS", "http://127.0.0.1:1")
	t.Setenv("NB_PYROSCOPE_USER", "user")
	t.Setenv("NB_PYROSCOPE_PASSWORD", "token")

	started.Store(true)
	t.Cleanup(func() { started.Store(false) })
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	stop := Start("netbird-second")
	stop()

	assert.True(t, started.Load(), "the running profiler must stay marked as started")
	entry := hook.LastEntry()
	require.NotNil(t, entry, "the skipped start must be logged")
	assert.Equal(t, log.WarnLevel, entry.Level)
	assert.Contains(t, entry.Message, "already running")
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected config
		errIs    error
		wantErr  bool
	}{
		{
			name:  "address unset disables profiling",
			errIs: errNotConfigured,
		},
		{
			name:  "empty address disables profiling",
			env:   map[string]string{"NB_PYROSCOPE_ADDRESS": ""},
			errIs: errNotConfigured,
		},
		{
			name: "credentials without address disable profiling",
			env: map[string]string{
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			errIs: errNotConfigured,
		},
		{
			name: "address without credentials fails",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS": "https://profiles-prod-001.grafana.net",
			},
			wantErr: true,
		},
		{
			name: "address with empty credentials fails",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "https://profiles-prod-001.grafana.net",
				"NB_PYROSCOPE_USER":     "",
				"NB_PYROSCOPE_PASSWORD": "",
			},
			wantErr: true,
		},
		{
			name: "address without password fails",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS": "https://profiles-prod-001.grafana.net",
				"NB_PYROSCOPE_USER":    "123456",
			},
			wantErr: true,
		},
		{
			name: "full configuration",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "https://profiles-prod-001.grafana.net",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			expected: config{
				Address:  "https://profiles-prod-001.grafana.net",
				User:     "123456",
				Password: "token",
			},
		},
		{
			name: "http to loopback is allowed",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "http://127.0.0.1:4040",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			expected: config{
				Address:  "http://127.0.0.1:4040",
				User:     "123456",
				Password: "token",
			},
		},
		{
			name: "http to localhost is allowed",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "http://localhost:4040",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			expected: config{
				Address:  "http://localhost:4040",
				User:     "123456",
				Password: "token",
			},
		},
		{
			name: "http to private network is allowed",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "http://10.0.0.5:4040",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			expected: config{
				Address:  "http://10.0.0.5:4040",
				User:     "123456",
				Password: "token",
			},
		},
		{
			name: "http to public host is rejected",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "http://pyroscope.example.com",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			wantErr: true,
		},
		{
			name: "http to public address is rejected",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "http://203.0.113.10:4040",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			wantErr: true,
		},
		{
			name: "address without scheme is rejected",
			env: map[string]string{
				"NB_PYROSCOPE_ADDRESS":  "pyroscope.example.com:4040",
				"NB_PYROSCOPE_USER":     "123456",
				"NB_PYROSCOPE_PASSWORD": "token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := loadConfig()

			switch {
			case tt.errIs != nil:
				require.ErrorIs(t, err, tt.errIs)
			case tt.wantErr:
				require.Error(t, err)
				require.NotErrorIs(t, err, errNotConfigured)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.expected, cfg)
			}
		})
	}
}

func TestStartWithoutConfigurationIsNoop(t *testing.T) {
	clearEnv(t)

	stop := Start("netbird-test")
	require.NotNil(t, stop)
	stop()
}

func clearEnv(t *testing.T) {
	t.Helper()

	for _, k := range []string{"NB_PYROSCOPE_ADDRESS", "NB_PYROSCOPE_USER", "NB_PYROSCOPE_PASSWORD"} {
		t.Setenv(k, "")
		require.NoError(t, os.Unsetenv(k))
	}
}
