//go:build !windows

package getent

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePasswd(t *testing.T) {
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
			u, shell, err := parsePasswd(tt.input)
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

func TestParseGroup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantGroup   *user.Group
		wantMembers []string
		wantErr     bool
	}{
		{
			name:      "no members",
			input:     "vma:x:1000:\n",
			wantGroup: &user.Group{Name: "vma", Gid: "1000"},
		},
		{
			name:        "one member",
			input:       "sudo:x:27:alice",
			wantGroup:   &user.Group{Name: "sudo", Gid: "27"},
			wantMembers: []string{"alice"},
		},
		{
			name:        "several members",
			input:       "docker:x:998:alice,bob\n",
			wantGroup:   &user.Group{Name: "docker", Gid: "998"},
			wantMembers: []string{"alice", "bob"},
		},
		{
			name:    "too few fields",
			input:   "bad:x",
			wantErr: true,
		},
		{
			name:    "empty group name",
			input:   ":x:1000:alice",
			wantErr: true,
		},
		{
			name:    "empty GID",
			input:   "vma:x::alice",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, members, err := parseGroup(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantGroup.Name, g.Name, "group name")
			assert.Equal(t, tt.wantGroup.Gid, g.Gid, "GID")
			assert.Equal(t, tt.wantMembers, members, "members")
		})
	}
}

func TestGroupMembersFromFile(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  []string
	}{
		{name: "no members", entry: "vma:x:1000:"},
		{name: "only the owner", entry: "vma:x:1000:vma", want: []string{"vma"}},
		{name: "two members", entry: "vma:x:1000:vma,bob", want: []string{"vma", "bob"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "group")
			body := "root:x:0:\n" + tt.entry + "\nsudo:x:27:vma\n"
			require.NoError(t, os.WriteFile(path, []byte(body), 0o644), "write the group file")

			members, err := groupMembersFromFile(path, "vma")
			require.NoError(t, err, "entry %q", tt.entry)
			assert.Equal(t, tt.want, members, "entry %q", tt.entry)
		})
	}
}

// A group the file does not describe, because it comes from LDAP or another
// NSS source, is an error rather than an empty member list: the caller must
// be able to tell "no members" from "no answer".
func TestGroupMembersFromFileUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "group")
	require.NoError(t, os.WriteFile(path, []byte("root:x:0:\n"), 0o644), "write the group file")

	_, err := groupMembersFromFile(path, "vma")
	assert.Error(t, err, "a group the file does not describe")

	_, err = groupMembersFromFile(filepath.Join(t.TempDir(), "absent"), "vma")
	assert.Error(t, err, "no group file at all")
}

// GroupMembers on the root group, which every Unix has, whichever source
// answers for it.
func TestGroupMembers_RootGroup(t *testing.T) {
	rootGroup := "root"
	switch runtime.GOOS {
	case "darwin", "dragonfly", "freebsd", "netbsd", "openbsd":
		rootGroup = "wheel"
	}

	_, err := GroupMembers(rootGroup)
	assert.NoError(t, err, "the %s group must be describable", rootGroup)
}

func TestValidateInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"normal username", "alice", true},
		{"numeric UID", "1001", true},
		{"dots and underscores", "alice.bob_test", true},
		{"hyphen", "alice-bob", true},
		{"leading hyphen rejected", "-i", false},
		{"leading double hyphen rejected", "--no-idn", false},
		{"lone hyphen rejected", "-", false},
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
			assert.Equal(t, tt.want, validateInput(tt.input))
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

func TestPasswdLookup_RootUser(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	u, shell, err := passwdLookup("root")
	require.NoError(t, err)
	assert.Equal(t, "root", u.Username)
	assert.Equal(t, "0", u.Uid)
	assert.Equal(t, "0", u.Gid)
	assert.NotEmpty(t, shell, "root should have a shell")
}

func TestPasswdLookup_ByUID(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	u, _, err := passwdLookup("0")
	require.NoError(t, err)
	assert.Equal(t, "root", u.Username)
	assert.Equal(t, "0", u.Uid)
}

func TestPasswdLookup_NonexistentUser(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	_, _, err := passwdLookup("nonexistent_user_xyzzy_12345")
	assert.Error(t, err)
}

func TestPasswdLookup_InvalidInput(t *testing.T) {
	_, _, err := passwdLookup("")
	assert.Error(t, err)

	_, _, err = passwdLookup("user\x00name")
	assert.Error(t, err)
}

func TestPasswdLookup_NotAvailable(t *testing.T) {
	if _, err := exec.LookPath("getent"); err == nil {
		t.Skip("getent is available, can't test missing case")
	}

	_, _, err := passwdLookup("root")
	assert.Error(t, err, "should fail when getent is not installed")
}

func TestGroupLookup_RootGroup(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	g, _, err := groupLookup("0")
	require.NoError(t, err)
	assert.Equal(t, "0", g.Gid, "GID 0 resolves to the root group")
	assert.NotEmpty(t, g.Name, "the root group has a name")
}

func TestIdGroups_CurrentUser(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	groups, err := idGroups(current.Username)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "current user should have at least one group")

	for _, gid := range groups {
		_, err := strconv.ParseUint(gid, 10, 32)
		assert.NoError(t, err, "group ID %q should be a valid uint32", gid)
	}
}

func TestIdGroups_NonexistentUser(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id not available on this system")
	}

	_, err := idGroups("nonexistent_user_xyzzy_12345")
	assert.Error(t, err)
}

func TestIdGroups_InvalidInput(t *testing.T) {
	_, err := idGroups("")
	assert.Error(t, err)

	_, err = idGroups("user\x00name")
	assert.Error(t, err)
}

func TestGetentResultsMatchStdlib(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this system")
	}

	current, err := user.Current()
	require.NoError(t, err)

	getentUser, _, err := passwdLookup(current.Username)
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

	getentUser, _, err := passwdLookup(current.Uid)
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

	idGroupIDs, err := idGroups(current.Username)
	require.NoError(t, err)

	// Deduplicate both lists: id -G can return duplicates (e.g., root in Docker)
	// and ElementsMatch treats duplicates as distinct.
	assert.ElementsMatch(t, uniqueStrings(stdGroups), uniqueStrings(idGroupIDs), "id -G should return same groups as os/user")
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
