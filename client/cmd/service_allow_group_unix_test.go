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
	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// testAllowGroupPrincipal is a principal that resolves on any Unix host.
const testAllowGroupPrincipal = "gid:0"

func TestResolveAllowGroup_NumericGID(t *testing.T) {
	for _, value := range []string{"0", "gid:0"} {
		t.Run(value, func(t *testing.T) {
			principal, err := resolveAllowGroup(value)
			require.NoError(t, err)
			assert.Equal(t, ipcauth.KindGID, principal.Kind)
			assert.Equal(t, "gid:0", principal.String())
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
	assert.Equal(t, "gid:"+gid, principal.String())
}

// Spellings of the same GID must collapse to one principal, otherwise
// checkAllowGroupSet reads them as a request for two groups and refuses.
func TestResolveAllowGroups_CanonicalisesGIDs(t *testing.T) {
	resolved, err := resolveAllowGroups([]string{"gid:01", "gid:1", "1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"gid:1"}, resolved)
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
		// chown reads this as "leave the group alone", so applying it would
		// leave the socket on whatever group it already had.
		{name: "the unchanged-gid sentinel", value: "gid:4294967295"},
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
	// With nothing configured the socket already carries its final mode from
	// the bind, so this must not touch the path at all: a chmod here is the one
	// that could follow a symlink another account planted.
	t.Run("no principals leaves the socket alone", func(t *testing.T) {
		path := listenTestSocket(t)
		before := socketMode(t, path)

		require.NoError(t, applySocketAccess(path, nil))
		assert.Equal(t, before, socketMode(t, path))
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

	// A symlink standing where the listener put its socket is something another
	// account substituted, and chowning it as root would hand its target away.
	t.Run("a path that is not a socket is refused", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "nb-sock")
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

		target := filepath.Join(dir, "target")
		require.NoError(t, os.WriteFile(target, []byte("not a socket"), 0600))
		link := filepath.Join(dir, "d.sock")
		require.NoError(t, os.Symlink(target, link))

		gid := strconv.Itoa(os.Getgid())
		require.Error(t, applySocketAccess(link, []string{"gid:" + gid}))
		require.NoError(t, applySocketAccess(link, nil), "with nothing configured there is nothing to apply")

		// Either way the substituted target keeps the mode it was created with.
		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	// Restricting a socket in a directory other accounts can write to is
	// refused: they can replace the entry between the check and the change.
	t.Run("an untrusted socket directory is refused", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "nb-sock")
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
		require.NoError(t, os.Chmod(dir, 0777))

		path := filepath.Join(dir, "d.sock")
		listener, err := net.Listen("unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, listener.Close()) })

		gid := strconv.Itoa(os.Getgid())
		require.Error(t, applySocketAccess(path, []string{"gid:" + gid}))

		// Leaving it unrestricted is still allowed: that is the historical
		// behaviour and grants nothing the mode did not already grant.
		assert.NoError(t, applySocketAccess(path, nil))
	})
}

// The kernel checks a Unix socket's mode at connect(), not at accept(), so a
// socket that is briefly wider than intended can be connected to before the
// daemon narrows it, and that caller stays connected afterwards. The bind must
// therefore land on the final mode, whatever umask the service manager used.
func TestListenUnixPrivate_BindsAtTheFinalMode(t *testing.T) {
	// A umask the daemon might have inherited from its service manager. Nonzero
	// and not one of the masks under test, so it proves both that the bind mode
	// does not depend on it and that it is put back afterwards.
	const callerUmask = 0o027

	tests := []struct {
		name    string
		allowed []string
		want    os.FileMode
	}{
		{name: "unrestricted binds open, so nothing has to widen it later", want: 0666},
		{name: "restricted binds owner-only, for applySocketAccess to hand to the group",
			allowed: []string{"gid:0"}, want: 0600},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previous := syscall.Umask(callerUmask)
			t.Cleanup(func() { syscall.Umask(previous) })

			dir, err := os.MkdirTemp("", "nb-sock")
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

			path := filepath.Join(dir, "d.sock")
			listener, err := listenUnixPrivate(path, tc.allowed)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, listener.Close()) })

			// Immediately after the bind, so nothing else can have moved it.
			restored := syscall.Umask(callerUmask)
			assert.Equal(t, callerUmask, restored, "listenUnixPrivate must restore the umask it changed")

			assert.Equal(t, tc.want, socketMode(t, path))
		})
	}
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
