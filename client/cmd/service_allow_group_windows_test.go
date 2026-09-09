//go:build windows

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// accountName returns the name the local system knows a SID by.
func accountName(sid string) (string, error) {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return "", err
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil {
		return "", err
	}
	if domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}

// sidAdministrators is BUILTIN\Administrators, a group present on every
// Windows install, localised name and all.
const sidAdministrators = "S-1-5-32-544"

// testAllowGroupPrincipal is a principal that resolves on any Windows host.
const testAllowGroupPrincipal = "sid:" + sidAdministrators

func TestResolveAllowGroup_SID(t *testing.T) {
	for _, value := range []string{sidAdministrators, "sid:" + sidAdministrators, strings.ToLower(sidAdministrators)} {
		t.Run(value, func(t *testing.T) {
			principal, err := resolveAllowGroup(value)
			require.NoError(t, err)
			assert.Equal(t, "sid:"+sidAdministrators, principal)
		})
	}
}

func TestResolveAllowGroup_ByName(t *testing.T) {
	// The well-known SID resolves to whatever the account is called in this
	// install's language, and that name must resolve back to the same SID.
	name, err := accountName(sidAdministrators)
	require.NoError(t, err)

	principal, err := resolveAllowGroup(name)
	require.NoError(t, err)
	assert.Equal(t, "sid:"+sidAdministrators, principal)
}

func TestResolveAllowGroup_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "unix principal", value: "gid:0"},
		{name: "unknown kind", value: "user:alice"},
		{name: "malformed SID", value: "sid:S-1-not-a-sid"},
		{name: "unknown account", value: "no-such-account-08b1f0c4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveAllowGroup(tc.value)
			assert.Error(t, err)
		})
	}
}

// A pipe descriptor holds one ACE per principal, so any number is enforceable.
func TestCheckAllowGroupSet_AcceptsAny(t *testing.T) {
	assert.NoError(t, checkAllowGroupSet(nil))
	assert.NoError(t, checkAllowGroupSet([]string{"sid:" + sidAdministrators, "sid:S-1-5-18"}))
}

// A Unix socket on Windows carries no mode, so a restriction configured
// against one cannot be applied and must stop the daemon rather than leave the
// socket open to every local process.
func TestApplySocketAccess_UnixSocketCannotBeRestricted(t *testing.T) {
	assert.NoError(t, applySocketAccess(`C:\ProgramData\Netbird\netbird.sock`, nil),
		"an unrestricted unix socket is the historical behaviour and stays allowed")

	err := applySocketAccess(`C:\ProgramData\Netbird\netbird.sock`, []string{testAllowGroupPrincipal})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "npipe://", "the error should name the transport that can carry the restriction")
}

func TestAllowedPipeSDDL(t *testing.T) {
	t.Run("no principals leaves the pipe open", func(t *testing.T) {
		sddl, err := allowedPipeSDDL(nil)
		require.NoError(t, err)
		assert.Contains(t, sddl, "(A;;GA;;;WD)", "an unconfigured pipe stays open to every local caller")
	})

	t.Run("a principal replaces the Everyone ACE", func(t *testing.T) {
		sddl, err := allowedPipeSDDL([]string{"sid:S-1-5-21-1-2-3-1001"})
		require.NoError(t, err)
		assert.NotContains(t, sddl, "(A;;GA;;;WD)")
		assert.Contains(t, sddl, "(A;;GA;;;S-1-5-21-1-2-3-1001)")
		assert.Contains(t, sddl, "(A;;GA;;;SY)", "LocalSystem runs the daemon")
		assert.Contains(t, sddl, "(A;;GA;;;BA)", "an elevated caller is never locked out")
		assert.True(t, strings.HasPrefix(sddl, "D:P"), "the DACL must stay protected: %s", sddl)
	})

	t.Run("a principal of another platform is refused", func(t *testing.T) {
		_, err := allowedPipeSDDL([]string{"gid:0"})
		require.Error(t, err)
	})
}

// TestListenNamedPipe_RestrictedDescriptor covers only that a restricted
// descriptor is accepted by ListenPipe and the pipe is created. Whether the
// descriptor actually denies an outside principal is not asserted here: that
// needs a second account and a connect attempt, so it is covered by the
// allowedPipeSDDL assertions above plus manual testing.
func TestListenNamedPipe_RestrictedDescriptor(t *testing.T) {
	listener, path, err := listenNamedPipe("netbird-test-"+t.Name(), []string{"sid:" + sidAdministrators})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })
	assert.NotEmpty(t, path)
}
