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

// Reads must not write. A config file missing a field apply() fills in (MTU,
// here) is what used to trigger the write-back.
func TestReadsDoNotWriteTheConfigBack(t *testing.T) {
	denormalized := []byte(`{"WgIface":"wt0"}`)

	for name, read := range map[string]func(string) (*Config, error){
		"GetExistingConfig":    GetExistingConfig,
		"ReadOrGenerateConfig": ReadOrGenerateConfig,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			require.NoError(t, os.WriteFile(path, denormalized, 0o600))

			cfg, err := read(path)
			require.NoError(t, err)
			require.Equal(t, uint16(iface.DefaultMTU), cfg.MTU, "the returned config is still normalized in memory")
			require.Empty(t, cfg.PrivateKey, "a read must not mint an identity either")

			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, string(denormalized), string(after), "%s rewrote the config file", name)
		})
	}
}

// ReadConfig resolves a default config for a profile that has no file yet, and
// that must not create the file either.
func TestReadConfigDoesNotCreateTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")

	cfg, err := ReadOrGenerateConfig(path)
	require.NoError(t, err)
	require.Equal(t, DefaultManagementURL, cfg.ManagementURL.String())

	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err), "ReadConfig created the config file")
}

// The identity is the one thing a read cannot recompute, so it is provisioned
// on request and its caller persists it.
func TestEnsureIdentity(t *testing.T) {
	cfg := newConfigSkeleton()

	generated, err := cfg.EnsureIdentity()
	require.NoError(t, err)
	require.True(t, generated)
	require.NotEmpty(t, cfg.PrivateKey)
	require.NotEmpty(t, cfg.SSHKey)

	key := cfg.PrivateKey
	generated, err = cfg.EnsureIdentity()
	require.NoError(t, err)
	require.False(t, generated, "a config that already has an identity keeps it")
	require.Equal(t, key, cfg.PrivateKey)
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

	cfg, err := GetExistingConfig(path)
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

// The dry-run baseline exists to be compared against and discarded, so it must
// not mint keys — the CLI's login backoff loop would otherwise log a fresh
// "generated new Wireguard key" on every attempt.
func TestDryRunBaselineDoesNotGenerateKeys(t *testing.T) {
	baseline, err := newDryRunBaseline(filepath.Join(t.TempDir(), "absent.json"))
	require.NoError(t, err)

	require.Empty(t, baseline.PrivateKey, "generated a WireGuard key for a throwaway config")
	require.Empty(t, baseline.SSHKey, "generated an SSH key for a throwaway config")

	// Everything the comparison actually looks at is still the default config.
	require.Equal(t, DefaultManagementURL, baseline.ManagementURL.String())
	require.Equal(t, uint16(iface.DefaultMTU), baseline.MTU)
	require.Equal(t, iface.DefaultWgPort, baseline.WgPort)
}

// A stored profile can carry no identity — a mobile logout clears the keys in
// place — so the next config write has to mint one, which is what keeps the
// following login from dialing management with an empty key.
func TestUpdateConfigProvisionsAMissingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logged-out.json")
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    path,
		ManagementURL: "https://api.netbird.io:443",
	})
	require.NoError(t, err)

	// Stand in for the logout, which zeroes the keys and writes the config out.
	loggedOut, err := GetExistingConfig(path)
	require.NoError(t, err)
	loggedOut.PrivateKey = ""
	loggedOut.SSHKey = ""
	require.NoError(t, WriteOutConfig(path, loggedOut))

	cfg, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path})
	require.NoError(t, err)
	require.NotEmpty(t, cfg.PrivateKey, "the write path did not provision an identity")
	require.NotEmpty(t, cfg.SSHKey)

	persisted, err := GetExistingConfig(path)
	require.NoError(t, err)
	require.Equal(t, cfg.PrivateKey, persisted.PrivateKey, "the provisioned identity was not persisted")
}

// A config that carries no sync message version must not make the dry run
// panic: the gate runs inside a request handler, where failing closed is the
// worst acceptable outcome.
func TestWouldChangeWithoutAStoredSyncMessageVersion(t *testing.T) {
	cfg := seededConfig(t)
	require.Nil(t, cfg.SyncMessageVersion, "the fixture is only useful while the field starts out unset")

	version := 2
	changed, err := cfg.WouldChange(ConfigInput{SyncMessageVersion: &version})
	require.NoError(t, err)
	require.True(t, changed)
	require.Nil(t, cfg.SyncMessageVersion, "the dry run set the version on the stored config")
}

// Restating the certificate paths a config already holds is not a change, for
// the same reason restating any other value is not.
func TestWouldChangeIgnoresRestatedCertificatePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mtls.json")
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:        path,
		ManagementURL:     "https://api.netbird.io:443",
		ClientCertPath:    "/etc/netbird/client.crt",
		ClientCertKeyPath: "/etc/netbird/client.key",
	})
	require.NoError(t, err)

	cfg, err := GetExistingConfig(path)
	require.NoError(t, err)

	changed, err := cfg.WouldChange(ConfigInput{
		ClientCertPath:    "/etc/netbird/client.crt",
		ClientCertKeyPath: "/etc/netbird/client.key",
	})
	require.NoError(t, err)
	require.False(t, changed, "the stored certificate paths were restated")

	changed, err = cfg.WouldChange(ConfigInput{ClientCertPath: "/etc/netbird/other.crt"})
	require.NoError(t, err)
	require.True(t, changed, "a different certificate path is a change")
}
