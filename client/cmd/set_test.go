package cmd

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/stretchr/testify/require"
)

func TestSetCommand_AllSettings(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write empty JSON object to the config file to avoid JSON parse errors
	_, err = tempFile.WriteString("{}")
	require.NoError(t, err)
	tempFile.Close()

	configPath = tempFile.Name()

	tests := []struct {
		setting string
		value   string
		verify  func(*testing.T, *internal.Config)
		wantErr bool
	}{
		{"management-url", "https://test.mgmt:443", func(t *testing.T, c *internal.Config) {
			require.Equal(t, "https://test.mgmt:443", c.ManagementURL.String())
		}, false},
		{"admin-url", "https://test.admin:443", func(t *testing.T, c *internal.Config) {
			require.Equal(t, "https://test.admin:443", c.AdminURL.String())
		}, false},
		{"interface-name", "utun99", func(t *testing.T, c *internal.Config) {
			require.Equal(t, "utun99", c.WgIface)
		}, false},
		{"external-ip-map", "12.34.56.78,12.34.56.79", func(t *testing.T, c *internal.Config) {
			require.Equal(t, []string{"12.34.56.78", "12.34.56.79"}, c.NATExternalIPs)
		}, false},
		{"extra-iface-blacklist", "eth1,eth2", func(t *testing.T, c *internal.Config) {
			require.Contains(t, c.IFaceBlackList, "eth1")
			require.Contains(t, c.IFaceBlackList, "eth2")
		}, false},
		{"dns-resolver-address", "127.0.0.1:5053", func(t *testing.T, c *internal.Config) {
			require.Equal(t, "127.0.0.1:5053", c.CustomDNSAddress)
		}, false},
		{"extra-dns-labels", "vpc1,mgmt1", func(t *testing.T, c *internal.Config) {
			require.True(t, strings.Contains(c.DNSLabels.SafeString(), "vpc1"))
			require.True(t, strings.Contains(c.DNSLabels.SafeString(), "mgmt1"))
		}, false},
		{"preshared-key", "testkey", func(t *testing.T, c *internal.Config) {
			require.Equal(t, "testkey", c.PreSharedKey)
		}, false},
		{"enable-rosenpass", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.RosenpassEnabled)
		}, false},
		{"rosenpass-permissive", "false", func(t *testing.T, c *internal.Config) {
			require.False(t, c.RosenpassPermissive)
		}, false},
		{"allow-server-ssh", "true", func(t *testing.T, c *internal.Config) {
			require.NotNil(t, c.ServerSSHAllowed)
			require.True(t, *c.ServerSSHAllowed)
		}, false},
		{"network-monitor", "false", func(t *testing.T, c *internal.Config) {
			require.NotNil(t, c.NetworkMonitor)
			require.False(t, *c.NetworkMonitor)
		}, false},
		{"disable-auto-connect", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.DisableAutoConnect)
		}, false},
		{"disable-client-routes", "false", func(t *testing.T, c *internal.Config) {
			require.False(t, c.DisableClientRoutes)
		}, false},
		{"disable-server-routes", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.DisableServerRoutes)
		}, false},
		{"disable-dns", "false", func(t *testing.T, c *internal.Config) {
			require.False(t, c.DisableDNS)
		}, false},
		{"disable-firewall", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.DisableFirewall)
		}, false},
		{"block-lan-access", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.BlockLANAccess)
		}, false},
		{"block-inbound", "false", func(t *testing.T, c *internal.Config) {
			require.False(t, c.BlockInbound)
		}, false},
		{"enable-lazy-connection", "true", func(t *testing.T, c *internal.Config) {
			require.True(t, c.LazyConnectionEnabled)
		}, false},
		{"wireguard-port", "51820", func(t *testing.T, c *internal.Config) {
			require.Equal(t, 51820, c.WgPort)
		}, false},
		{"dns-router-interval", "2m", func(t *testing.T, c *internal.Config) {
			require.Equal(t, 2*time.Minute, c.DNSRouteInterval)
		}, false},
		// Invalid cases
		{"enable-rosenpass", "notabool", nil, true},
		{"wireguard-port", "notanint", nil, true},
		{"dns-router-interval", "notaduration", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.setting+"="+tt.value, func(t *testing.T) {
			args := []string{tt.setting, tt.value}
			err := setFunc(nil, args)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			config, err := internal.ReadConfig(configPath)
			require.NoError(t, err)
			if tt.verify != nil {
				tt.verify(t, config)
			}
		})
	}
}

func TestSetCommand_EnvVars(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write empty JSON object to the config file to avoid JSON parse errors
	_, err = tempFile.WriteString("{}")
	require.NoError(t, err)
	tempFile.Close()

	configPath = tempFile.Name()

	os.Setenv("NB_INTERFACE_NAME", "utun77")
	defer os.Unsetenv("NB_INTERFACE_NAME")
	args := []string{"interface-name", "utun99"}
	err = setFunc(nil, args)
	require.NoError(t, err)
	config, err := internal.ReadConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, "utun77", config.WgIface)

	os.Unsetenv("NB_INTERFACE_NAME")
	os.Setenv("WT_INTERFACE_NAME", "utun88")
	defer os.Unsetenv("WT_INTERFACE_NAME")
	err = setFunc(nil, args)
	require.NoError(t, err)
	config, err = internal.ReadConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, "utun88", config.WgIface)

	os.Unsetenv("WT_INTERFACE_NAME")
	// No env var, should use CLI value
	err = setFunc(nil, args)
	require.NoError(t, err)
	config, err = internal.ReadConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, "utun99", config.WgIface)
}
