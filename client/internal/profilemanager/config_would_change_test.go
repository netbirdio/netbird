package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/domain"
)

func seededConfig(t *testing.T) *Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "seeded.json")
	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    path,
		ManagementURL: "https://api.netbird.io:443",
		PreSharedKey:  strPointer("stored-key"),
	})
	require.NoError(t, err)
	return cfg
}

func strPointer(s string) *string { return &s }

func TestWouldChange(t *testing.T) {
	tests := []struct {
		name  string
		input ConfigInput
		want  bool
	}{
		{name: "empty input", input: ConfigInput{}, want: false},
		{name: "same management URL", input: ConfigInput{ManagementURL: "https://api.netbird.io:443"}, want: false},
		{name: "management URL without its default port", input: ConfigInput{ManagementURL: "https://api.netbird.io"}, want: false},
		{name: "different management URL", input: ConfigInput{ManagementURL: "https://other.example:443"}, want: true},
		{name: "same pre-shared key", input: ConfigInput{PreSharedKey: strPointer("stored-key")}, want: false},
		{name: "redacted pre-shared key", input: ConfigInput{PreSharedKey: strPointer("**********")}, want: false},
		{name: "different pre-shared key", input: ConfigInput{PreSharedKey: strPointer("other-key")}, want: true},
		{name: "new interface blacklist entry", input: ConfigInput{ExtraIFaceBlackList: []string{"nb-probe0"}}, want: true},
		{name: "blacklist entry already present", input: ConfigInput{ExtraIFaceBlackList: []string{"lo"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := seededConfig(t)

			changed, err := cfg.WouldChange(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, changed)
		})
	}
}

// The dry run must not be observable on the config it is run against: it
// decides whether a write is allowed, it does not perform one.
func TestWouldChangeLeavesTheConfigAlone(t *testing.T) {
	cfg := seededConfig(t)
	blacklist := len(cfg.IFaceBlackList)

	changed, err := cfg.WouldChange(ConfigInput{
		ManagementURL:       "https://other.example:443",
		PreSharedKey:        strPointer("other-key"),
		ExtraIFaceBlackList: []string{"nb-probe0"},
		DNSLabels:           domain.FromPunycodeList([]string{"probe"}),
		NATExternalIPs:      []string{"1.2.3.4"},
	})
	require.NoError(t, err)
	require.True(t, changed)

	require.Equal(t, "https://api.netbird.io:443", cfg.ManagementURL.String())
	require.Equal(t, "stored-key", cfg.PreSharedKey)
	require.Len(t, cfg.IFaceBlackList, blacklist)
	require.Empty(t, cfg.DNSLabels)
	require.Empty(t, cfg.NATExternalIPs)
}

// A nil config means the profile holds nothing yet, so the baseline is what
// the daemon would create for it.
func TestWouldChangeWithoutAStoredConfig(t *testing.T) {
	var cfg *Config

	changed, err := cfg.WouldChange(ConfigInput{})
	require.NoError(t, err)
	require.False(t, changed, "a request carrying nothing cannot change anything")

	changed, err = cfg.WouldChange(ConfigInput{ManagementURL: DefaultManagementURL})
	require.NoError(t, err)
	require.False(t, changed, "the default management URL is what would be written anyway")

	changed, err = cfg.WouldChange(ConfigInput{ManagementURL: "https://other.example:443"})
	require.NoError(t, err)
	require.True(t, changed)
}

func TestWouldChangeReportsAnInvalidInput(t *testing.T) {
	cfg := seededConfig(t)

	_, err := cfg.WouldChange(ConfigInput{ManagementURL: "not-a-url"})
	require.Error(t, err)
}
