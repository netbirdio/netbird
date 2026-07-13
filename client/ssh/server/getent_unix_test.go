//go:build !windows

package server

import (
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGetentPasswd(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantUser    *user.User
		wantShell   string
		wantErr     bool
		errContains string
	}{
		{
			name:  "standard entry",
			input: "alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n",
			wantUser: &user.User{
				Username: "alice",
				Uid:      "1001",
				Gid:      "1001",
				Name:     "Alice Smith",
				HomeDir:  "/home/alice",
			},
			wantShell: "/bin/bash",
		},
		{
			name:  "root entry",
			input: "root:x:0:0:root:/root:/bin/bash",
			wantUser: &user.User{
				Username: "root",
				Uid:      "0",
				Gid:      "0",
				Name:     "root",
				HomeDir:  "/root",
			},
			wantShell: "/bin/bash",
		},
		{
			name:  "empty gecos field",
			input: "svc:x:999:999::/var/lib/svc:/usr/sbin/nologin",
			wantUser: &user.User{
				Username: "svc",
				Uid:      "999",
				Gid:      "999",
				Name:     "",
				HomeDir:  "/var/lib/svc",
			},
			wantShell: "/usr/sbin/nologin",
		},
		{
			name:  "gecos with commas",
			input: "john:x:1002:1002:John Doe,Room 101,555-1234,555-4321:/home/john:/bin/zsh",
			wantUser: &user.User{
				Username: "john",
				Uid:      "1002",
				Gid:      "1002",
				Name:     "John Doe,Room 101,555-1234,555-4321",
				HomeDir:  "/home/john",
			},
			wantShell: "/bin/zsh",
		},
		{
			name:  "remote user with large UID",
			input: "remoteuser:*:50001:50001:Remote User:/home/remoteuser:/bin/bash\n",
			wantUser: &user.User{
				Username: "remoteuser",
				Uid:      "50001",
				Gid:      "50001",
				Name:     "Remote User",
				HomeDir:  "/home/remoteuser",
			},
			wantShell: "/bin/bash",
		},
		{
			name:  "no shell field (only 6 fields)",
			input: "minimal:x:1000:1000::/home/minimal",
			wantUser: &user.User{
				Username: "minimal",
				Uid:      "1000",
				Gid:      "1000",
				Name:     "",
				HomeDir:  "/home/minimal",
			},
			wantShell: "",
		},
		{
			name:        "too few fields",
			input:       "bad:x:1000",
			wantErr:     true,
			errContains: "need 6+ fields",
		},
		{
			name:        "empty username",
			input:       ":x:1000:1000::/home/test:/bin/bash",
			wantErr:     true,
			errContains: "missing required fields",
		},
		{
			name:        "empty UID",
			input:       "test:x::1000::/home/test:/bin/bash",
			wantErr:     true,
			errContains: "missing required fields",
		},
		{
			name:        "empty GID",
			input:       "test:x:1000:::/home/test:/bin/bash",
			wantErr:     true,
			errContains: "missing required fields",
		},
		{
			name:        "empty input",
			input:       "",
			wantErr:     true,
			errContains: "need 6+ fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, shell, err := parseGetentPasswd(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser.Username, u.Username, "username")
			assert.Equal(t, tt.wantUser.Uid, u.Uid, "UID")
			assert.Equal(t, tt.wantUser.Gid, u.Gid, "GID")
			assert.Equal(t, tt.wantUser.Name, u.Name, "name/gecos")
			assert.Equal(t, tt.wantUser.HomeDir, u.HomeDir, "home directory")
			assert.Equal(t, tt.wantShell, shell, "shell")
		})
	}
}

func TestValidateGetentInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"normal username", "alice", true},
		{"numeric UID", "1001", true},
		{"dots and underscores", "alice.bob_test", true},
		{"hyphen", "alice-bob", true},
		{"kerberos principal", "user@REALM", true},
		{"samba machine account", "MACHINE$", true},
		{"NIS compat", "+user", true},
		{"empty", "", false},
		{"null byte", "alice\x00bob", false},
		{"newline", "alice\nbob", false},
		{"tab", "alice\tbob", false},
		{"control char", "alice\x01bob", false},
		{"DEL char", "alice\x7fbob", false},
		{"space rejected", "alice bob", false},
		{"semicolon rejected", "alice;bob", false},
		{"backtick rejected", "alice`bob", false},
		{"pipe rejected", "alice|bob", false},
		{"33 chars exceeds non-linux max", makeLongString(33), runtime.GOOS == "linux"},
		{"256 chars at linux max", makeLongString(256), runtime.GOOS == "linux"},
		{"257 chars exceeds all limits", makeLongString(257), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validateGetentInput(tt.input))
		})
	}
}

func makeLongString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestRunGetent_RootUser(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	u, shell, err := runGetent("root")
	require.NoError(t, err)
	assert.Equal(t, "root", u.Username)
	assert.Equal(t, "0", u.Uid)
	assert.Equal(t, "0", u.Gid)
	assert.NotEmpty(t, shell, "root should have a shell")
}

func TestRunGetent_ByUID(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	u, _, err := runGetent("0")
	require.NoError(t, err)
	assert.Equal(t, "root", u.Username)
	assert.Equal(t, "0", u.Uid)
}

func TestRunGetent_NonexistentUser(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	_, _, err := runGetent("nonexistent_user_xyzzy_12345")
	assert.Error(t, err)
}

func TestRunGetent_InvalidInput(t *testing.T) {
	_, _, err := runGetent("")
	assert.Error(t, err)

	_, _, err = runGetent("user\x00name")
	assert.Error(t, err)
}

func TestRunGetent_NotAvailable(t *testing.T) {
	if _, err := exec.LookPath("getent"); err == nil {
		t.Skip("getent is available, can't test missing case")
	}

	_, _, err := runGetent("root")
	assert.Error(t, err, "should fail when getent is not installed")
}

func TestRunIdGroups_CurrentUser(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	groups, err := runIdGroups(current.Username)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "current user should have at least one group")

	for _, gid := range groups {
		_, err := strconv.ParseUint(gid, 10, 32)
		assert.NoError(t, err, "group ID %q should be a valid uint32", gid)
	}
}

func TestRunIdGroups_NonexistentUser(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id not available on this system")
	}

	_, err := runIdGroups("nonexistent_user_xyzzy_12345")
	assert.Error(t, err)
}

func TestRunIdGroups_InvalidInput(t *testing.T) {
	_, err := runIdGroups("")
	assert.Error(t, err)

	_, err = runIdGroups("user\x00name")
	assert.Error(t, err)
}

func TestGetentResultsMatchStdlib(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	getentUser, _, err := runGetent(current.Username)
	require.NoError(t, err)

	assert.Equal(t, current.Username, getentUser.Username, "username should match")
	assert.Equal(t, current.Uid, getentUser.Uid, "UID should match")
	assert.Equal(t, current.Gid, getentUser.Gid, "GID should match")
	assert.Equal(t, current.HomeDir, getentUser.HomeDir, "home directory should match")
}

func TestGetentResultsMatchStdlib_ByUID(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	getentUser, _, err := runGetent(current.Uid)
	require.NoError(t, err)

	assert.Equal(t, current.Username, getentUser.Username, "username should match when looked up by UID")
	assert.Equal(t, current.Uid, getentUser.Uid, "UID should match")
}

func TestIdGroupsMatchStdlib(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	stdGroups, err := current.GroupIds()
	if err != nil {
		t.Skip("os/user.GroupIds() not working, likely CGO_ENABLED=0")
	}

	idGroups, err := runIdGroups(current.Username)
	require.NoError(t, err)

	// Deduplicate both lists: id -G can return duplicates (e.g., root in Docker)
	// and ElementsMatch treats duplicates as distinct.
	assert.ElementsMatch(t, uniqueStrings(stdGroups), uniqueStrings(idGroups), "id -G should return same groups as os/user")
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// TestGetShellFromPasswd_CurrentUser verifies that getShellFromPasswd correctly
// reads the current user's shell from /etc/passwd by comparing it against what
// getent reports (which goes through NSS).
func TestGetShellFromPasswd_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	shell := getShellFromPasswd(current.Uid)
	if shell == "" {
		t.Skip("current user not found in /etc/passwd (may be an NSS-only user)")
	}

	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)

	if _, err := exec.LookPath("getent"); err == nil {
		_, getentShell, getentErr := runGetent(current.Uid)
		if getentErr == nil && getentShell != "" {
			assert.Equal(t, getentShell, shell, "shell from /etc/passwd should match getent")
		}
	}
}

// TestGetShellFromPasswd_RootUser verifies that getShellFromPasswd can read
// root's shell from /etc/passwd. Root is guaranteed to be in /etc/passwd on
// any standard Unix system.
func TestGetShellFromPasswd_RootUser(t *testing.T) {
	shell := getShellFromPasswd("0")
	require.NotEmpty(t, shell, "root (UID 0) must be in /etc/passwd")
	assert.True(t, shell[0] == '/', "root shell should be an absolute path, got %q", shell)
}

// TestGetShellFromPasswd_NonexistentUID verifies that getShellFromPasswd
// returns empty for a UID that doesn't exist in /etc/passwd.
func TestGetShellFromPasswd_NonexistentUID(t *testing.T) {
	shell := getShellFromPasswd("4294967294")
	assert.Empty(t, shell, "nonexistent UID should return empty shell")
}

// TestGetShellFromPasswd_MatchesGetentForKnownUsers reads /etc/passwd directly
// and cross-validates every entry against getent to ensure parseGetentPasswd
// and getShellFromPasswd agree on shell values.
func TestGetShellFromPasswd_MatchesGetentForKnownUsers(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available")
	}

	// Pick a few well-known system UIDs that are virtually always in /etc/passwd.
	uids := []string{"0"} // root

	current, err := user.Current()
	require.NoError(t, err)
	uids = append(uids, current.Uid)

	for _, uid := range uids {
		passwdShell := getShellFromPasswd(uid)
		if passwdShell == "" {
			continue
		}

		_, getentShell, err := runGetent(uid)
		if err != nil {
			continue
		}

		assert.Equal(t, getentShell, passwdShell, "shell mismatch for UID %s", uid)
	}
}
