//go:build linux

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLookup builds a policy directory in the shape of /etc/selinux/targeted and a lookup
// whose kernel query is replaced by a fixed answer.
func newTestLookup(t *testing.T, seusers, defaultContexts string, userFiles map[string]string, reachable []string) *selinuxLookup {
	t.Helper()

	root := t.TempDir()
	policy := filepath.Join(root, "targeted")
	require.NoError(t, os.MkdirAll(filepath.Join(policy, "contexts", "users"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "config"), []byte("SELINUX=enforcing\nSELINUXTYPE=targeted\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(policy, "seusers"), []byte(seusers), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(policy, "contexts", "default_contexts"), []byte(defaultContexts), 0o644))
	for name, content := range userFiles {
		require.NoError(t, os.WriteFile(filepath.Join(policy, "contexts", "users", name), []byte(content), 0o644))
	}

	return &selinuxLookup{
		rootDir: root,
		reachable: func(from, seuser string) ([]string, error) {
			return reachable, nil
		},
	}
}

const testDefaultContexts = `system_r:local_login_t:s0	user_r:user_t:s0 staff_r:staff_t:s0 unconfined_r:unconfined_t:s0
system_r:sshd_t:s0		user_r:user_t:s0 staff_r:staff_t:s0 sysadm_r:sysadm_t:s0 unconfined_r:unconfined_t:s0
`

func TestDefaultContext(t *testing.T) {
	seusers := `# comment
root:unconfined_u:s0-s0:c0.c1023
selu:user_u:s0
%wheel:staff_u:s0-s0:c0.c1023
__default__:unconfined_u:s0-s0:c0.c1023
`

	tests := []struct {
		name      string
		username  string
		groups    []string
		userFiles map[string]string
		reachable []string
		want      string
		wantErr   bool
	}{
		{
			name:      "confined user gets the user domain, not an unconfined one",
			username:  "selu",
			reachable: []string{"user_u:user_r:oddjob_mkhomedir_t:s0", "user_u:user_r:user_t:s0"},
			want:      "user_u:user_r:user_t:s0",
		},
		{
			name:      "unknown user falls back to the default mapping",
			username:  "vma",
			reachable: []string{"unconfined_u:system_r:nx_server_t:s0-s0:c0.c1023", "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"},
			want:      "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
		},
		{
			name:      "group mapping applies when there is no exact entry",
			username:  "alice",
			groups:    []string{"users", "wheel"},
			reachable: []string{"staff_u:staff_r:staff_t:s0-s0:c0.c1023", "staff_u:system_r:nx_server_t:s0-s0:c0.c1023"},
			want:      "staff_u:staff_r:staff_t:s0-s0:c0.c1023",
		},
		{
			name:      "per-user file preference wins over default contexts",
			username:  "selu",
			userFiles: map[string]string{"user_u": "system_r:sshd_t:s0\tuser_r:oddjob_mkhomedir_t:s0 user_r:user_t:s0\n"},
			reachable: []string{"user_u:user_r:user_t:s0", "user_u:user_r:oddjob_mkhomedir_t:s0"},
			want:      "user_u:user_r:oddjob_mkhomedir_t:s0",
		},
		{
			name:      "preferences the policy does not reach are skipped",
			username:  "root",
			reachable: []string{"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"},
			want:      "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
		},
		{
			name:      "reachable contexts nobody prefers are not chosen",
			username:  "selu",
			reachable: []string{"user_u:system_r:nx_server_t:s0", "user_u:user_r:container_t:s0"},
			wantErr:   true,
		},
		{
			name:      "nothing reachable denies",
			username:  "selu",
			reachable: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newTestLookup(t, seusers, testDefaultContexts, tt.userFiles, tt.reachable)
			got, err := l.defaultContext(tt.username, tt.groups)
			if tt.wantErr {
				assert.Error(t, err, "an unresolvable context must refuse the session")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultContext_MissingSEUsers(t *testing.T) {
	l := newTestLookup(t, "", testDefaultContexts, nil, []string{"user_u:user_r:user_t:s0"})
	_, err := l.defaultContext("nobody", nil)
	assert.Error(t, err, "no seusers entry and no default entry must deny")
}

func TestPolicyType(t *testing.T) {
	root := t.TempDir()
	assert.Equal(t, "targeted", policyType(root), "a missing config defaults to targeted")

	require.NoError(t, os.WriteFile(filepath.Join(root, "config"), []byte("SELINUX=enforcing\nSELINUXTYPE = mls\n"), 0o644))
	assert.Equal(t, "mls", policyType(root))
}

func TestParseContextReply(t *testing.T) {
	got, err := parseContextReply([]byte("2\x00user_u:user_r:user_t:s0\x00user_u:user_r:container_t:s0\x00"))
	require.NoError(t, err)
	assert.Equal(t, []string{"user_u:user_r:user_t:s0", "user_u:user_r:container_t:s0"}, got)

	got, err = parseContextReply([]byte("0\x00"))
	require.NoError(t, err)
	assert.Empty(t, got)

	_, err = parseContextReply([]byte("3\x00user_u:user_r:user_t:s0\x00"))
	assert.Error(t, err, "a count that does not match the contexts must be rejected")

	_, err = parseContextReply(nil)
	assert.Error(t, err)
}

func TestRoleType(t *testing.T) {
	assert.Equal(t, "user_r:user_t", roleType("user_u:user_r:user_t:s0-s0:c0.c1023"))
	assert.Equal(t, "user_r:user_t", roleType("user_r:user_t:s0"))
	assert.Equal(t, "user_r:user_t", roleType("user_r:user_t"))
}

func TestWriteExecContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exec")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	require.NoError(t, writeExecContext(path, "user_u:user_r:user_t:s0"))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "user_u:user_r:user_t:s0", string(got), "the context is written without a trailing newline")

	assert.Error(t, writeExecContext(filepath.Join(t.TempDir(), "missing"), "x"))
}

func TestIsConfined(t *testing.T) {
	seusers := "selu:user_u:s0\nroot:unconfined_u:s0-s0:c0.c1023\n%wheel:staff_u:s0\n__default__:unconfined_u:s0-s0:c0.c1023\n"
	l := newTestLookup(t, seusers, testDefaultContexts, nil, nil)

	assert.True(t, l.isConfined("selu", nil), "a user mapped to user_u is confined")
	assert.False(t, l.isConfined("root", nil), "a user mapped to unconfined_u is not")
	assert.False(t, l.isConfined("vma", nil), "an unlisted user takes the default mapping")
	assert.True(t, l.isConfined("alice", []string{"wheel"}), "a group mapping applies")

	empty := newTestLookup(t, "", testDefaultContexts, nil, nil)
	assert.True(t, empty.isConfined("vma", nil), "a user that cannot be mapped is treated as confined")
}

func TestReadEnforcing(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "enforce")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}

	assert.True(t, readEnforcing(write("1")), "enforcing")
	assert.False(t, readEnforcing(write("0")), "permissive")
	assert.True(t, readEnforcing(filepath.Join(dir, "missing")), "an unreadable state counts as enforcing")
}

func TestHasPolicy(t *testing.T) {
	l := newTestLookup(t, "__default__:unconfined_u:s0\n", testDefaultContexts, nil, nil)
	assert.True(t, l.hasPolicy(), "seusers present")

	assert.False(t, (&selinuxLookup{rootDir: t.TempDir()}).hasPolicy(), "a host without policy files, such as a container, has none")
}
