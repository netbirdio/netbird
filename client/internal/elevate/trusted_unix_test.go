//go:build !windows

package elevate

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerOnlyDir is t.TempDir() with the write bits tightened. testing creates its
// numbered directory with 0777 minus the umask, so under the common 002 umask it
// is group-writable and would fail the check under test on its own.
func ownerOnlyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755), "tighten the temporary directory")
	return dir
}

// writeExecutable creates a plain executable file, the shape trustedSelf checks.
func writeExecutable(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "netbird-ui")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755), "write the executable")
	require.NoError(t, os.Chmod(path, 0o755), "set the executable's mode")
	return path
}

func TestCheckOnlyOwnerWritableAcceptsOwnerOnly(t *testing.T) {
	err := checkOnlyOwnerWritable(writeExecutable(t, ownerOnlyDir(t)))
	assert.NoError(t, err, "an owner-only writable executable is trustworthy")
}

func TestCheckOnlyOwnerWritableRejectsWorldWritableFile(t *testing.T) {
	path := writeExecutable(t, ownerOnlyDir(t))
	require.NoError(t, os.Chmod(path, 0o777), "make the executable world-writable")

	assert.Error(t, checkOnlyOwnerWritable(path), "a world-writable executable must be refused")
}

// The permission policy on its own, without a filesystem to arrange: whether the
// group has been vouched for is the only thing that makes group write acceptable.
func TestWriteBitsAllow(t *testing.T) {
	tests := []struct {
		name         string
		perm         os.FileMode
		sticky       bool
		groupAllowed bool
		wantErr      bool
	}{
		{name: "owner only", perm: 0o755},
		{name: "group write in a private group", perm: 0o775, groupAllowed: true},
		{name: "group write in a shared group", perm: 0o775, wantErr: true},
		{name: "world write", perm: 0o777, groupAllowed: true, wantErr: true},
		{name: "world write on a sticky directory", perm: 0o777, sticky: true},
		{name: "group write on a sticky directory", perm: 0o775, sticky: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := writeBitsAllow("/path", tt.perm, tt.sticky, tt.groupAllowed)
			if tt.wantErr {
				assert.Error(t, err, "perm %v, sticky %v, group allowed %v", tt.perm, tt.sticky, tt.groupAllowed)
				return
			}
			assert.NoError(t, err, "perm %v, sticky %v, group allowed %v", tt.perm, tt.sticky, tt.groupAllowed)
		})
	}
}

// A build under a home directory on a distribution with a 002 umask, which is what
// a locally built or tarball-installed binary looks like. Its group has no members
// but its owner, so it is as good as owner-only.
//
// Whether this host is such a distribution is read from the environment rather than
// from groupWriteAllowed: asking the function under test whether to run would let
// it skip its own coverage away if it regressed to refusing everything.
func TestCheckOnlyOwnerWritableAcceptsOwnPrivateGroup(t *testing.T) {
	requirePrivatePrimaryGroup(t)

	dir := ownerOnlyDir(t)
	path := writeExecutable(t, dir)
	require.NoError(t, os.Chmod(dir, 0o775), "make the directory group-writable")
	require.NoError(t, os.Chmod(path, 0o775), "make the executable group-writable")

	err := checkOnlyOwnerWritable(path)
	assert.NoError(t, err, "group write in the owner's own private group reaches nobody else")
}

// A group that shares its owner's name but has gained another member is no longer
// private, and its write access reaches an account that could not elevate.
func TestGroupHasOtherMembers(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  bool
	}{
		{name: "no members", entry: "vma:x:1000:"},
		{name: "only the owner", entry: "vma:x:1000:vma"},
		{name: "another member", entry: "vma:x:1000:bob", want: true},
		{name: "the owner and another", entry: "vma:x:1000:vma,bob", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "group")
			body := "root:x:0:\n" + tt.entry + "\nsudo:x:27:vma\n"
			require.NoError(t, os.WriteFile(path, []byte(body), 0o644), "write the group file")

			assert.Equal(t, tt.want, groupHasOtherMembers(path, "vma", "vma"), "entry %q", tt.entry)
		})
	}
}

// A group file that says nothing about the group leaves the name as the only thing
// to go on, so the private-group allowance stands rather than collapsing on every
// host whose groups come from LDAP.
func TestGroupHasOtherMembersTolerantOfAnUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "group")
	require.NoError(t, os.WriteFile(path, []byte("root:x:0:\n"), 0o644), "write the group file")

	assert.False(t, groupHasOtherMembers(path, "vma", "vma"), "a group the file does not describe")
	assert.False(t, groupHasOtherMembers(filepath.Join(t.TempDir(), "absent"), "vma", "vma"),
		"no group file at all")
}

// A writable directory is as good as a writable file: whoever can write the
// directory can put a different binary at the same path.
func TestCheckOnlyOwnerWritableRejectsWritableDirectory(t *testing.T) {
	dir := filepath.Join(ownerOnlyDir(t), "bin")
	require.NoError(t, os.Mkdir(dir, 0o755), "create the directory")
	path := writeExecutable(t, dir)
	require.NoError(t, os.Chmod(dir, 0o777), "make the directory world-writable")

	assert.Error(t, checkOnlyOwnerWritable(path), "an executable in a world-writable directory must be refused")
}

// A sticky world-writable directory is exempt: the sticky bit is what stops one
// user replacing another's entries. /tmp is why this matters.
func TestCheckOnlyOwnerWritableAcceptsStickyDirectory(t *testing.T) {
	dir := filepath.Join(ownerOnlyDir(t), "sticky")
	require.NoError(t, os.Mkdir(dir, 0o755), "create the directory")
	path := writeExecutable(t, dir)
	require.NoError(t, os.Chmod(dir, 0o777|os.ModeSticky), "make the directory sticky and world-writable")

	err := checkOnlyOwnerWritable(path)
	assert.NoError(t, err, "the sticky bit stops another user replacing the executable")
}

func TestCheckOnlyOwnerWritableRejectsMissingFile(t *testing.T) {
	err := checkOnlyOwnerWritable(filepath.Join(ownerOnlyDir(t), "absent"))
	assert.Error(t, err, "an executable that is not there must be refused")
}

// requirePrivatePrimaryGroup skips unless this user's primary group is their own,
// which is what the user-private-group allowance is about.
func requirePrivatePrimaryGroup(t *testing.T) {
	t.Helper()

	self, err := user.Current()
	require.NoError(t, err, "look up the test user")
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	require.NoError(t, err, "look up the test user's primary group")

	if group.Name != self.Username {
		t.Skipf("the test user's primary group is %q, not their own, so there is nothing to assert here", group.Name)
	}
	if groupHasOtherMembers(groupFile, group.Name, self.Username) {
		t.Skipf("group %q has other members, so it is not a private group", group.Name)
	}
}
