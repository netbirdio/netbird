package profilemanager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/util"
)

type mockMgmProber struct{}

func (m *mockMgmProber) HealthCheck() error {
	return nil
}

func (m *mockMgmProber) Close() error { return nil }

func TestGetConfig(t *testing.T) {
	// case 1: new default config has to be generated
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), DefaultManagementURL)
	assert.Equal(t, config.AdminURL.String(), DefaultAdminURL)

	managementURL := "https://test.management.url:33071"
	adminURL := "https://app.admin.url:443"
	path := filepath.Join(t.TempDir(), "config.json")
	preSharedKey := "preSharedKey"

	// case 2: new config has to be generated
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: managementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Errorf("config file was expected to be created under path %s", path)
	}

	// case 3: existing config -> fetch it
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: managementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	// case 4: existing config, but new managementURL has been provided -> update config
	newManagementURL := "https://test.newManagement.url:33071"
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: newManagementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), newManagementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	// read once more to make sure that config file has been updated with the new management URL
	readConf, err := util.ReadJson(path, config)
	if err != nil {
		return
	}
	assert.Equal(t, readConf.(*Config).ManagementURL.String(), newManagementURL)
}

func TestExtraIFaceBlackList(t *testing.T) {
	extraIFaceBlackList := []string{"eth1"}
	path := filepath.Join(t.TempDir(), "config.json")
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:          path,
		ExtraIFaceBlackList: extraIFaceBlackList,
	})
	if err != nil {
		return
	}

	assert.Contains(t, config.IFaceBlackList, "eth1")
	readConf, err := util.ReadJson(path, config)
	if err != nil {
		return
	}

	assert.Contains(t, readConf.(*Config).IFaceBlackList, "eth1")
}

func TestHiddenPreSharedKey(t *testing.T) {
	hidden := "**********"
	samplePreSharedKey := "mysecretpresharedkey"
	tests := []struct {
		name         string
		preSharedKey *string
		want         string
	}{
		{"nil", nil, ""},
		{"hidden", &hidden, ""},
		{"filled", &samplePreSharedKey, samplePreSharedKey},
	}

	// generate default cfg
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	_, _ = UpdateOrCreateConfig(ConfigInput{
		ConfigPath: cfgFile,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := UpdateOrCreateConfig(ConfigInput{
				ConfigPath:   cfgFile,
				PreSharedKey: tt.preSharedKey,
			})
			if err != nil {
				t.Fatalf("failed to get cfg: %s", err)
			}

			if cfg.PreSharedKey != tt.want {
				t.Fatalf("invalid preshared key: '%s', expected: '%s' ", cfg.PreSharedKey, tt.want)
			}
		})
	}
}

func TestNewProfileDefaults(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: configPath,
	})
	require.NoError(t, err, "should create new config")

	assert.Equal(t, DefaultManagementURL, config.ManagementURL.String(), "ManagementURL should have default")
	assert.Equal(t, DefaultAdminURL, config.AdminURL.String(), "AdminURL should have default")
	assert.NotEmpty(t, config.PrivateKey, "PrivateKey should be generated")
	assert.NotEmpty(t, config.SSHKey, "SSHKey should be generated")
	assert.Equal(t, iface.WgInterfaceDefault, config.WgIface, "WgIface should have default")
	assert.Equal(t, iface.DefaultWgPort, config.WgPort, "WgPort should default to 51820")
	assert.Equal(t, uint16(iface.DefaultMTU), config.MTU, "MTU should have default")
	assert.Equal(t, dynamic.DefaultInterval, config.DNSRouteInterval, "DNSRouteInterval should have default")
	assert.NotNil(t, config.ServerSSHAllowed, "ServerSSHAllowed should be set")
	assert.NotNil(t, config.DisableNotifications, "DisableNotifications should be set")
	assert.NotEmpty(t, config.IFaceBlackList, "IFaceBlackList should have defaults")

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		assert.NotNil(t, config.NetworkMonitor, "NetworkMonitor should be set on Windows/macOS")
		assert.True(t, *config.NetworkMonitor, "NetworkMonitor should be enabled by default on Windows/macOS")
	}
}

func TestWireguardPortZeroExplicit(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Create a new profile with explicit port 0 (random port)
	explicitZero := 0
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    configPath,
		WireguardPort: &explicitZero,
	})
	require.NoError(t, err, "should create config with explicit port 0")

	assert.Equal(t, 0, config.WgPort, "WgPort should be 0 when explicitly set by user")

	// Verify it persists
	readConfig, err := GetConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, 0, readConfig.WgPort, "WgPort should remain 0 after reading from file")
}

func TestWireguardPortDefaultVsExplicit(t *testing.T) {
	tests := []struct {
		name          string
		wireguardPort *int
		expectedPort  int
		description   string
	}{
		{
			name:          "no port specified uses default",
			wireguardPort: nil,
			expectedPort:  iface.DefaultWgPort,
			description:   "When user doesn't specify port, default to 51820",
		},
		{
			name:          "explicit zero for random port",
			wireguardPort: func() *int { v := 0; return &v }(),
			expectedPort:  0,
			description:   "When user explicitly sets 0, use 0 for random port",
		},
		{
			name:          "explicit custom port",
			wireguardPort: func() *int { v := 52000; return &v }(),
			expectedPort:  52000,
			description:   "When user sets custom port, use that port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.json")

			config, err := UpdateOrCreateConfig(ConfigInput{
				ConfigPath:    configPath,
				WireguardPort: tt.wireguardPort,
			})
			require.NoError(t, err, tt.description)
			assert.Equal(t, tt.expectedPort, config.WgPort, tt.description)
		})
	}
}

func TestUpdateConfigServerSSHAllowedNotSet(t *testing.T) {
	// Configs written before ServerSSHAllowed was introduced lack the field and
	// unmarshal to nil. Supplying the SSH server flag on top of such a config must
	// apply the value instead of panicking on a nil pointer dereference.
	tests := []struct {
		name  string
		input *bool
		want  bool
	}{
		{"enable", util.True(), true},
		{"disable", util.False(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0600))

			config, err := UpdateConfig(ConfigInput{
				ConfigPath:       configPath,
				ServerSSHAllowed: tt.input,
			})
			require.NoError(t, err)
			require.NotNil(t, config.ServerSSHAllowed, "ServerSSHAllowed should be set from input")
			assert.Equal(t, tt.want, *config.ServerSSHAllowed)
		})
	}
}

func TestUpdateConfigRemoteJobsAllowed(t *testing.T) {
	// Unlike SSH (which defaults on for legacy configs), remote jobs are an
	// explicit opt-in: a pre-existing config with no value materializes to off.
	t.Run("legacy config defaults off", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0600))

		config, err := UpdateConfig(ConfigInput{ConfigPath: configPath})
		require.NoError(t, err)
		require.NotNil(t, config.RemoteJobsAllowed, "RemoteJobsAllowed should be materialized")
		assert.False(t, *config.RemoteJobsAllowed, "remote jobs must default off")
	})

	for _, tt := range []struct {
		name  string
		input *bool
		want  bool
	}{
		{"enable", util.True(), true},
		{"disable", util.False(), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0600))

			config, err := UpdateConfig(ConfigInput{ConfigPath: configPath, RemoteJobsAllowed: tt.input})
			require.NoError(t, err)
			require.NotNil(t, config.RemoteJobsAllowed)
			assert.Equal(t, tt.want, *config.RemoteJobsAllowed)
		})
	}
}

func TestApplyMDMPolicyRemoteJobs(t *testing.T) {
	t.Run("enables remote jobs and sets the upload URL override", func(t *testing.T) {
		cfg := &Config{}
		cfg.applyMDMPolicy(mdm.NewPolicy(map[string]any{
			mdm.KeyRemoteJobsAllowed: true,
			mdm.KeyBundleUploadURL:   "https://upload.example.com",
		}))
		require.NotNil(t, cfg.RemoteJobsAllowed)
		assert.True(t, *cfg.RemoteJobsAllowed, "MDM allowRemoteJobs must enable the flag")
		assert.Equal(t, "https://upload.example.com", cfg.DebugBundleUploadURL, "MDM upload URL override must be applied")
	})

	t.Run("a non-https upload URL is rejected", func(t *testing.T) {
		cfg := &Config{}
		cfg.applyMDMPolicy(mdm.NewPolicy(map[string]any{
			mdm.KeyBundleUploadURL: "http://insecure.example.com",
		}))
		assert.Empty(t, cfg.DebugBundleUploadURL, "a non-https upload URL must be skipped")
	})

	t.Run("dropping the key clears a previously-applied override", func(t *testing.T) {
		cfg := &Config{DebugBundleUploadURL: "https://old.example.com"}
		// A replacement policy that no longer carries the key must not leave
		// the old upload target directing bundles.
		cfg.applyMDMPolicy(mdm.NewPolicy(map[string]any{mdm.KeyRemoteJobsAllowed: true}))
		assert.Empty(t, cfg.DebugBundleUploadURL, "the stale upload URL override must be cleared")
	})

	t.Run("an empty replacement policy clears a previously-applied override", func(t *testing.T) {
		cfg := &Config{DebugBundleUploadURL: "https://old.example.com"}
		// A policy that becomes empty entirely hits the IsEmpty early return;
		// the override must still be cleared rather than surviving on the
		// reused Config instance.
		cfg.applyMDMPolicy(mdm.NewPolicy(map[string]any{}))
		assert.Empty(t, cfg.DebugBundleUploadURL, "the stale upload URL override must be cleared when the policy empties")
	})

	t.Run("an invalid upload URL clears a previously-applied override (fail closed)", func(t *testing.T) {
		cfg := &Config{DebugBundleUploadURL: "https://old.example.com"}
		cfg.applyMDMPolicy(mdm.NewPolicy(map[string]any{mdm.KeyBundleUploadURL: "not-a-url"}))
		assert.Empty(t, cfg.DebugBundleUploadURL, "an invalid override must fail closed, not keep the stale target")
	})
}

func TestUpdateOldManagementURL(t *testing.T) {
	origProber := newMgmProber
	newMgmProber = func(_ context.Context, _ string, _ wgtypes.Key, _ bool) (mgmProber, error) {
		return &mockMgmProber{}, nil
	}
	t.Cleanup(func() { newMgmProber = origProber })

	tests := []struct {
		name                  string
		previousManagementURL string
		expectedManagementURL string
		fileShouldNotChange   bool
	}{
		{
			name:                  "Update old management URL with legacy port",
			previousManagementURL: "https://api.wiretrustee.com:33073",
			expectedManagementURL: DefaultManagementURL,
		},
		{
			name:                  "Update old management URL",
			previousManagementURL: oldDefaultManagementURL,
			expectedManagementURL: DefaultManagementURL,
		},
		{
			name:                  "No update needed when management URL is up to date",
			previousManagementURL: DefaultManagementURL,
			expectedManagementURL: DefaultManagementURL,
			fileShouldNotChange:   true,
		},
		{
			name:                  "No update needed when not using cloud management",
			previousManagementURL: "https://netbird.example.com:33073",
			expectedManagementURL: "https://netbird.example.com:33073",
			fileShouldNotChange:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.json")
			config, err := UpdateOrCreateConfig(ConfigInput{
				ManagementURL: tt.previousManagementURL,
				ConfigPath:    configPath,
			})
			require.NoError(t, err, "failed to create testing config")
			previousContent, err := os.ReadFile(configPath)
			require.NoError(t, err, "failed to read initial config")
			resultConfig, err := UpdateOldManagementURL(context.TODO(), config, configPath)
			require.NoError(t, err, "got error when updating old management url")
			require.Equal(t, tt.expectedManagementURL, resultConfig.ManagementURL.String())
			newContent, err := os.ReadFile(configPath)
			require.NoError(t, err, "failed to read updated config")
			if tt.fileShouldNotChange {
				require.Equal(t, string(previousContent), string(newContent), "file should not change")
			} else {
				require.NotEqual(t, string(previousContent), string(newContent), "file should have changed")
			}
		})
	}
}
