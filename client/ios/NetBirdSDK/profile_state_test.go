//go:build ios

package NetBirdSDK

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
			configPath: "/private/var/mobile/Containers/Shared/AppGroup/ABC/profiles/default/netbird.cfg",
			want:       "/private/var/mobile/Containers/Shared/AppGroup/ABC/profiles/default/netbird.account.json",
		},
		{
			name:       "named profile",
			configPath: "/private/var/mobile/Containers/Shared/AppGroup/ABC/profiles/work/netbird.cfg",
			want:       "/private/var/mobile/Containers/Shared/AppGroup/ABC/profiles/work/netbird.account.json",
		},
		{
			name:       "empty path is rejected",
			configPath: "",
			wantErr:    true,
		},
		{
			name:       "directory path is rejected",
			configPath: "/profiles/work/..",
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

// Every profile owns a directory, so two profiles must never share an account
// file even though their config files have the same name.
func TestProfileAccountPathIsPerProfile(t *testing.T) {
	root := "/profiles"

	defaultAccount, err := profileAccountPathFor(filepath.Join(root, "default", "netbird.cfg"))
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}

	workAccount, err := profileAccountPathFor(filepath.Join(root, "work", "netbird.cfg"))
	if err != nil {
		t.Fatalf("work profile: %v", err)
	}

	if defaultAccount == workAccount {
		t.Fatalf("two profiles share an account file: %q", defaultAccount)
	}
}

// The account file must never land on the engine's state file: both live in the
// profile directory, and the state manager rewrites the whole file from its own
// keys, so sharing a path would have the two overwrite each other.
func TestProfileAccountPathAvoidsEngineStateFile(t *testing.T) {
	dir := "/profiles/default"

	account, err := profileAccountPathFor(filepath.Join(dir, "netbird.cfg"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if account == filepath.Join(dir, "state.json") {
		t.Errorf("account file collides with the engine state file: %q", account)
	}
}

func TestWriteThenReadProfileEmail(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "profiles", "work", "netbird.cfg")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("prepare dir: %v", err)
	}

	if got := readProfileEmail(configPath); got != "" {
		t.Errorf("expected no email before a login, got %q", got)
	}

	const email = "user@example.com"
	if err := writeProfileEmail(configPath, email); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := readProfileEmail(configPath); got != email {
		t.Errorf("got %q, want %q", got, email)
	}

	if err := removeProfileEmail(configPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := readProfileEmail(configPath); got != "" {
		t.Errorf("expected no email after logout, got %q", got)
	}

	// Logout may run on a never-logged-in profile, so a second remove must pass.
	if err := removeProfileEmail(configPath); err != nil {
		t.Fatalf("second remove should be a no-op: %v", err)
	}
}

func TestWriteProfileEmailIgnoresEmpty(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "profiles", "work", "netbird.cfg")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("prepare dir: %v", err)
	}

	const email = "user@example.com"
	if err := writeProfileEmail(configPath, email); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeProfileEmail(configPath, ""); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	if got := readProfileEmail(configPath); got != email {
		t.Errorf("empty write clobbered the stored email: got %q, want %q", got, email)
	}
}

// The exported wrappers are what the host app calls; they must agree with the
// package-internal helpers the login flow uses.
func TestExportedAccountHelpers(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "profiles", "work", "netbird.cfg")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("prepare dir: %v", err)
	}

	const email = "user@example.com"
	if err := writeProfileEmail(configPath, email); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := ProfileAccountEmail(configPath); got != email {
		t.Errorf("ProfileAccountEmail: got %q, want %q", got, email)
	}
	if err := ClearProfileAccountEmail(configPath); err != nil {
		t.Fatalf("ClearProfileAccountEmail: %v", err)
	}
	if got := ProfileAccountEmail(configPath); got != "" {
		t.Errorf("email survived the clear: %q", got)
	}
	if got := ProfileAccountEmail(""); got != "" {
		t.Errorf("an unresolvable path must degrade to \"\", got %q", got)
	}
}
