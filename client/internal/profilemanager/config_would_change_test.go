package profilemanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
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

// GetConfig persists the normalization it performs; PeekConfig must not, so a
// caller that only inspects the stored settings leaves the file alone.
func TestPeekConfigDoesNotWriteBack(t *testing.T) {
	// A config file missing a field apply() fills in (MTU) is what makes the
	// normalization write fire.
	denormalized := []byte(`{"WgIface":"wt0"}`)

	peekPath := filepath.Join(t.TempDir(), "peek.json")
	require.NoError(t, os.WriteFile(peekPath, denormalized, 0o600))
	before, err := os.ReadFile(peekPath)
	require.NoError(t, err)

	cfg, err := PeekConfig(peekPath)
	require.NoError(t, err)
	require.Equal(t, uint16(iface.DefaultMTU), cfg.MTU, "the returned config is still normalized in memory")

	after, err := os.ReadFile(peekPath)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "PeekConfig rewrote the config file")

	// Same file through GetConfig, which is expected to persist it.
	getPath := filepath.Join(t.TempDir(), "get.json")
	require.NoError(t, os.WriteFile(getPath, denormalized, 0o600))

	_, err = GetConfig(getPath)
	require.NoError(t, err)

	persisted, err := os.ReadFile(getPath)
	require.NoError(t, err)
	require.NotEqual(t, string(denormalized), string(persisted), "GetConfig is the variant that normalizes on disk")
}

// One endpoint written several ways is one endpoint. A gate that compared
// spellings refused a client restating its own management URL with a trailing
// slash, which is a normal way to write it.
func TestSameServiceURL(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com:443", want: true},
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com/", want: true},
		{a: "https://mgmt.example.com/", b: "https://mgmt.example.com:443/", want: true},
		{a: "https://MGMT.example.com", b: "https://mgmt.example.com", want: true},
		{a: "http://mgmt.example.com", b: "http://mgmt.example.com:80", want: true},
		{a: "https://mgmt.example.com", b: "http://mgmt.example.com", want: false},
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com:8443", want: false},
		{a: "https://mgmt.example.com", b: "https://other.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			a, err := ParseServiceURL("a", tt.a)
			require.NoError(t, err)
			b, err := ParseServiceURL("b", tt.b)
			require.NoError(t, err)

			require.Equal(t, tt.want, SameServiceURL(a, b))
			require.Equal(t, tt.want, SameServiceURL(b, a), "the comparison must be symmetric")
		})
	}
}

// The same spellings, through the dry run the update-settings gate uses.
func TestWouldChangeIgnoresURLSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seeded.json")
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    path,
		ManagementURL: "https://mgmt.example.com",
	})
	require.NoError(t, err)

	cfg, err := GetConfig(path)
	require.NoError(t, err)

	for _, spelling := range []string{
		"https://mgmt.example.com",
		"https://mgmt.example.com/",
		"https://mgmt.example.com:443",
		"https://mgmt.example.com:443/",
		"https://MGMT.example.com",
	} {
		changed, err := cfg.WouldChange(ConfigInput{ManagementURL: spelling})
		require.NoError(t, err)
		require.False(t, changed, "%q is the stored endpoint written differently", spelling)
	}

	changed, err := cfg.WouldChange(ConfigInput{ManagementURL: "https://mgmt.example.com:8443"})
	require.NoError(t, err)
	require.True(t, changed, "a different port is a different endpoint")
}
