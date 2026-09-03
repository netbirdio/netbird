package mobile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileAccountPathFor(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		want       string
		wantErr    bool
	}{
		{
			name:       "default profile",
			configPath: "/data/netbird/files/netbird.cfg",
			want:       filepath.FromSlash("/data/netbird/files/netbird.account.json"),
		},
		{
			name:       "id profile",
			configPath: "/data/netbird/files/profiles/4c5f5c8198c3989cffb5b5394f5a7ae0.json",
			want:       filepath.FromSlash("/data/netbird/files/profiles/4c5f5c8198c3989cffb5b5394f5a7ae0.account.json"),
		},
		{
			name:       "legacy name-keyed profile is handled the same way",
			configPath: "/data/netbird/files/profiles/work.json",
			want:       filepath.FromSlash("/data/netbird/files/profiles/work.account.json"),
		},
		{
			name:       "empty path is rejected",
			configPath: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := profileAccountPathFor(tt.configPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got path %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProfileAccountPathForDefaultDoesNotCollide(t *testing.T) {
	root := "/data/netbird/files"

	defaultAccount, err := profileAccountPathFor(filepath.Join(root, defaultConfigFilename))
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}

	idAccount, err := profileAccountPathFor(filepath.Join(root, profilesSubdir, "abc123.json"))
	if err != nil {
		t.Fatalf("id profile: %v", err)
	}

	if defaultAccount == idAccount {
		t.Fatalf("default and id profile share an account file: %q", defaultAccount)
	}
}

// The account file must never land on the engine state file: on mobile both
// resolve under configDir, and the state manager rewrites the whole file from
// its own keys, so sharing a path would have the two overwrite each other. The
// expected names here mirror ProfileManager.GetStateFilePath.
func TestProfileAccountPathAvoidsEngineStateFile(t *testing.T) {
	root := "/data/netbird/files"

	cases := []struct {
		configPath  string
		engineState string
	}{
		{
			configPath:  filepath.Join(root, defaultConfigFilename),
			engineState: filepath.Join(root, "state.json"),
		},
		{
			configPath:  filepath.Join(root, profilesSubdir, "abc123.json"),
			engineState: filepath.Join(root, profilesSubdir, "abc123.state.json"),
		},
	}

	for _, c := range cases {
		account, err := profileAccountPathFor(c.configPath)
		if err != nil {
			t.Fatalf("%s: %v", c.configPath, err)
		}
		if account == c.engineState {
			t.Errorf("account file collides with the engine state file: %q", account)
		}
	}
}

func TestWriteThenReadProfileEmail(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "profiles", "abc123.json")
	if err := ensureDirFor(t, configPath); err != nil {
		t.Fatalf("prepare dir: %v", err)
	}

	if got := ReadProfileEmail(configPath); got != "" {
		t.Errorf("expected no email before a login, got %q", got)
	}

	const email = "user@example.com"
	if err := WriteProfileEmail(configPath, email); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := ReadProfileEmail(configPath); got != email {
		t.Errorf("got %q, want %q", got, email)
	}

	if err := removeProfileEmail(configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := ReadProfileEmail(configPath); got != "" {
		t.Errorf("expected no email after removal, got %q", got)
	}

	// Removal may run on a never-logged-in profile, so a second remove must pass.
	if err := removeProfileEmail(configPath); err != nil {
		t.Fatalf("second remove should be a no-op: %v", err)
	}
}

func TestWriteProfileEmailIgnoresEmpty(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "profiles", "abc123.json")
	if err := ensureDirFor(t, configPath); err != nil {
		t.Fatalf("prepare dir: %v", err)
	}

	const email = "user@example.com"
	if err := WriteProfileEmail(configPath, email); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteProfileEmail(configPath, ""); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	if got := ReadProfileEmail(configPath); got != email {
		t.Errorf("empty write clobbered the stored email: got %q, want %q", got, email)
	}
}

func ensureDirFor(t *testing.T, path string) error {
	t.Helper()
	return os.MkdirAll(filepath.Dir(path), 0o700)
}
