package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	Server   testServerConfig `yaml:"server"`
	Internal string           `yaml:"-"`
}

type testServerConfig struct {
	Address           string           `yaml:"address" env:"APP_SERVER_ADDRESS" flag:"address,legacy-address"`
	BindAddress       netip.Addr       `yaml:"bindAddress"`
	AdvertisedAddress netip.Addr       `yaml:"advertisedAddress"`
	Enabled           bool             `yaml:"enabled"`
	LogLevel          string           `yaml:"logLevel"`
	Timeout           time.Duration    `yaml:"timeout"`
	Ports             []int            `yaml:"ports"`
	Owner             *testOwnerConfig `yaml:"owner,omitempty"`
	TLS               testTLSConfig    `yaml:"tls"`
	JSONValue         testJSONValue    `yaml:"jsonValue"`
}

type testOwnerConfig struct {
	Email string `yaml:"email"`
}

type testTLSConfig struct {
	Enabled bool `yaml:"enabled"`
}

type testJSONValue struct {
	Value string
}

func (v *testJSONValue) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &v.Value)
}

type recursiveConfig struct {
	Value string           `yaml:"value"`
	Next  *recursiveConfig `yaml:"next,omitempty"`
}

func defaultTestConfig() *testConfig {
	return &testConfig{
		Server: testServerConfig{
			Address:  ":443",
			LogLevel: "info",
			Timeout:  30 * time.Second,
			Ports:    []int{443},
		},
		Internal: "default-internal",
	}
}

func TestLoadAppliesFileEnvironmentAndDefaults(t *testing.T) {
	configPath := writeConfigFile(t, "config.conf", `
server:
  bindAddress: 192.0.2.1
  enabled: yes
  logLevel: warn
  timeout: 5s
  ports: [80, 443]
  jsonValue: decoded
internal: ignored
`)
	t.Setenv("NB_SERVER_LOGLEVEL", "debug")
	t.Setenv("NB_SERVER_OWNER_EMAIL", "owner@example.com")
	t.Setenv("NB_SERVER_ADVERTISEDADDRESS", "198.51.100.1")

	cfg, err := Load(configPath, defaultTestConfig(), Options{
		TagName: "yaml",
	})
	require.NoError(t, err)
	assert.Equal(t, ":443", cfg.Server.Address, "Defaults should survive decoding")
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), cfg.Server.BindAddress, "Text values from files should be decoded")
	assert.Equal(t, netip.MustParseAddr("198.51.100.1"), cfg.Server.AdvertisedAddress, "Text values from the environment should be decoded")
	assert.True(t, cfg.Server.Enabled, "Legacy YAML booleans should be decoded")
	assert.Equal(t, "debug", cfg.Server.LogLevel, "Environment should override the file")
	assert.Equal(t, 5*time.Second, cfg.Server.Timeout, "Durations should be decoded")
	assert.Equal(t, []int{80, 443}, cfg.Server.Ports, "Slices should be decoded")
	assert.Equal(t, "decoded", cfg.Server.JSONValue.Value, "JSON unmarshalers should be decoded")
	require.NotNil(t, cfg.Server.Owner, "Environment should create optional nested configuration")
	assert.Equal(t, "owner@example.com", cfg.Server.Owner.Email, "Nested environment values should be decoded")
	assert.Equal(t, "default-internal", cfg.Internal, "Ignored fields should retain their defaults")
}

func TestLoadFlagPrecedence(t *testing.T) {
	configPath := writeConfigFile(t, "config.yaml", `
server:
  address: ":8443"
`)
	t.Setenv("APP_SERVER_ADDRESS", ":9443")
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("address", ":443", "")
	flags.String("legacy-address", ":443", "")
	require.NoError(t, flags.Set("legacy-address", ":7443"))

	cfg, err := Load(configPath, defaultTestConfig(), Options{
		TagName: "yaml",
		FlagSet: flags,
	})
	require.NoError(t, err)
	assert.Equal(t, ":7443", cfg.Server.Address, "Flags should override environment and file values")
}

func TestLoadAllowsEmptyEnvironmentOverrides(t *testing.T) {
	configPath := writeConfigFile(t, "config.yaml", `
server:
  address: ":8443"
`)
	t.Setenv("APP_SERVER_ADDRESS", "")

	cfg, err := Load(configPath, defaultTestConfig(), Options{
		TagName: "yaml",
	})
	require.NoError(t, err)
	assert.Empty(t, cfg.Server.Address, "An explicitly empty environment value should clear the file value")
}

func TestLoadTransformsConfig(t *testing.T) {
	t.Setenv("CONFIG_ADDRESS", ":8443")
	configPath := writeConfigFile(t, "config.yaml", `
server:
  address: "{{ .CONFIG_ADDRESS }}"
`)

	cfg, err := Load(configPath, defaultTestConfig(), Options{
		TagName:   "yaml",
		Transform: ExpandEnvTemplate,
	})
	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.Server.Address, "The transform should run before decoding")
}

func TestLoadUsesRecognizedFileType(t *testing.T) {
	configPath := writeConfigFile(t, "config.toml", `
[server]
address = ":8443"
enabled = true
`)

	cfg, err := Load(configPath, defaultTestConfig(), Options{TagName: "yaml"})
	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.Server.Address, "The file extension should select the decoder")
	assert.True(t, cfg.Server.Enabled, "TOML booleans should be decoded")
}

func TestLoadAllowsMissingFile(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{name: "empty path"},
		{name: "unknown extension", path: filepath.Join(t.TempDir(), "missing.conf")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("APP_SERVER_ADDRESS", ":9443")

			cfg, err := Load(testCase.path, defaultTestConfig(), Options{
				TagName:      "yaml",
				AllowMissing: true,
			})
			require.NoError(t, err)
			assert.Equal(t, ":9443", cfg.Server.Address, "Environment should override defaults without a file")
		})
	}
}

func TestLoadSupportsRecursiveConfigTypes(t *testing.T) {
	configPath := writeConfigFile(t, "config.yaml", `
value: first
next:
  value: second
`)

	cfg, err := Load(configPath, &recursiveConfig{}, Options{
		TagName: "yaml",
	})
	require.NoError(t, err)
	assert.Equal(t, "first", cfg.Value, "Root values should be decoded")
	require.NotNil(t, cfg.Next, "Recursive configuration should be decoded from the file")
	assert.Equal(t, "second", cfg.Next.Value, "Nested recursive values should be decoded")
}

func TestLoadRejectsMissingFileByDefault(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), defaultTestConfig(), Options{
		TagName: "yaml",
	})
	require.Error(t, err)
}

func TestLoadStrictRejectsUnknownKeys(t *testing.T) {
	configPath := writeConfigFile(t, "config.yaml", "unknown: true\n")

	_, err := Load(configPath, defaultTestConfig(), Options{
		TagName: "yaml",
		Strict:  true,
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid keys")
}

func TestLoadUsesTagAsDefaultFileType(t *testing.T) {
	configPath := writeConfigFile(t, "config.conf", "server:\n  address: :8443\n")

	cfg, err := Load(configPath, defaultTestConfig(), Options{TagName: "yaml"})
	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.Server.Address, "The struct tag should select the fallback decoder")
}

func TestLoadRejectsNilDefault(t *testing.T) {
	configPath := writeConfigFile(t, "config.yaml", "server: {}\n")

	_, err := Load(configPath, (*testConfig)(nil), Options{TagName: "yaml"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "default config is nil")
}

func writeConfigFile(t *testing.T, name, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))
	return configPath
}
