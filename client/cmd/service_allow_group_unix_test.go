//go:build !windows && !ios && !android

package cmd

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/getent"
)

// testAllowGroupPrincipal is a principal that resolves on any Unix host.
const testAllowGroupPrincipal = "gid:0"

func TestResolveAllowGroup_NumericGID(t *testing.T) {
	for _, value := range []string{"0", "gid:0"} {
		t.Run(value, func(t *testing.T) {
			principal, err := resolveAllowGroup(value)
			require.NoError(t, err)
			assert.Equal(t, "gid:0", principal)
		})
	}
}

func TestResolveAllowGroup_ByName(t *testing.T) {
	// The name of this process's primary group, so the test does not assume
	// what gid 0 is called: Linux says "root", macOS says "wheel".
	gid := strconv.Itoa(os.Getgid())
	group, err := getent.LookupGroupID(gid)
	if err != nil {
		t.Skipf("gid %s has no name on this host: %v", gid, err)
	}

	principal, err := resolveAllowGroup(group.Name)
	require.NoError(t, err)
	assert.Equal(t, "gid:"+gid, principal)
}

func TestResolveAllowGroup_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "windows principal", value: "sid:S-1-5-32-544"},
		{name: "unknown kind", value: "user:alice"},
		{name: "non-numeric gid", value: "gid:wheel"},
		{name: "negative gid", value: "gid:-1"},
		{name: "unknown group", value: "no-such-group-08b1f0c4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveAllowGroup(tc.value)
			assert.Error(t, err)
		})
	}
}

// A Unix socket carries one owning group, so a second one could not be
// enforced and must be refused rather than silently dropped.
func TestCheckAllowGroupSet_SingleGroupOnly(t *testing.T) {
	assert.NoError(t, checkAllowGroupSet(nil))
	assert.NoError(t, checkAllowGroupSet([]string{"gid:0"}))
	assert.Error(t, checkAllowGroupSet([]string{"gid:0", "gid:1"}))
}

func TestApplySocketAccess(t *testing.T) {
	t.Run("no principals leaves the socket open", func(t *testing.T) {
		path := listenTestSocket(t)

		require.NoError(t, applySocketAccess(path, nil))
		assert.Equal(t, os.FileMode(0666), socketMode(t, path))
	})

	t.Run("a principal hands the socket to that group", func(t *testing.T) {
		path := listenTestSocket(t)
		// The process's own primary group: chown to any other group needs
		// privileges the test does not have.
		gid := os.Getgid()

		require.NoError(t, applySocketAccess(path, []string{"gid:" + strconv.Itoa(gid)}))
		assert.Equal(t, os.FileMode(0660), socketMode(t, path))
		assert.Equal(t, uint32(gid), socketGID(t, path))
	})

	t.Run("a principal of another platform is refused", func(t *testing.T) {
		path := listenTestSocket(t)

		require.Error(t, applySocketAccess(path, []string{"sid:S-1-5-32-544"}))
	})

	t.Run("an unparseable gid is refused", func(t *testing.T) {
		path := listenTestSocket(t)

		require.Error(t, applySocketAccess(path, []string{"gid:wheel"}))
	})
}

func listenTestSocket(t *testing.T) string {
	t.Helper()

	// Short, because the sun_path of a Unix socket is about 100 bytes and
	// t.TempDir() embeds the test name.
	dir, err := os.MkdirTemp("", "nb-sock")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	path := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	return path
}

func socketMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func socketGID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "stat of %s is not a syscall.Stat_t", path)
	return stat.Gid
}
