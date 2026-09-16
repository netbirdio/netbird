//go:build !ios && !android

package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/mdm"
)

func TestResolveAllowGroups_NoValuesLeavesSocketOpen(t *testing.T) {
	for name, values := range map[string][]string{
		"nil":             nil,
		"empty slice":     {},
		"empty string":    {""},
		"only whitespace": {"  ", "\t"},
	} {
		t.Run(name, func(t *testing.T) {
			resolved, err := resolveAllowGroups(values)
			require.NoError(t, err)
			assert.Empty(t, resolved)
		})
	}
}

func TestResolveAllowGroups_Deduplicates(t *testing.T) {
	resolved, err := resolveAllowGroups([]string{testAllowGroupPrincipal, testAllowGroupPrincipal, " " + testAllowGroupPrincipal + " "})
	require.NoError(t, err)
	assert.Equal(t, []string{testAllowGroupPrincipal}, resolved)
}

func TestResolveAllowGroups_UnresolvableIsAnError(t *testing.T) {
	_, err := resolveAllowGroups([]string{"no-such-group-08b1f0c4"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-such-group-08b1f0c4")
}

func TestResolveAllowGroups_SplitsCommaSeparatedEntries(t *testing.T) {
	// One managed-configuration string listing several principals, as a
	// Windows REG_SZ delivers them.
	resolved, err := resolveAllowGroups([]string{testAllowGroupPrincipal + ", " + testAllowGroupPrincipal})
	require.NoError(t, err)
	assert.Equal(t, []string{testAllowGroupPrincipal}, resolved)
}

func TestDaemonSocketPrincipals(t *testing.T) {
	original := allowGroups
	t.Cleanup(func() { allowGroups = original })

	t.Run("no configuration leaves the sockets open", func(t *testing.T) {
		allowGroups = nil

		resolved, _, err := daemonSocketPrincipals(mdm.NewPolicy(nil))
		require.NoError(t, err)
		assert.Empty(t, resolved)
	})

	t.Run("the install-time flag applies when nothing is managed", func(t *testing.T) {
		allowGroups = []string{testAllowGroupPrincipal}

		resolved, source, err := daemonSocketPrincipals(mdm.NewPolicy(nil))
		require.NoError(t, err)
		assert.Equal(t, []string{testAllowGroupPrincipal}, resolved)
		assert.Contains(t, source, "--allow-group")
	})

	t.Run("an MDM policy overrides the install-time flag", func(t *testing.T) {
		allowGroups = nil
		policy := mdm.NewPolicy(map[string]any{mdm.KeyAllowGroups: testAllowGroupPrincipal})

		resolved, source, err := daemonSocketPrincipals(policy)
		require.NoError(t, err)
		assert.Equal(t, []string{testAllowGroupPrincipal}, resolved)
		assert.Contains(t, source, mdm.KeyAllowGroups)
	})

	t.Run("an empty MDM value lifts an install-time restriction", func(t *testing.T) {
		allowGroups = []string{testAllowGroupPrincipal}
		policy := mdm.NewPolicy(map[string]any{mdm.KeyAllowGroups: ""})

		resolved, source, err := daemonSocketPrincipals(policy)
		require.NoError(t, err)
		assert.Empty(t, resolved)
		assert.Contains(t, source, mdm.KeyAllowGroups)
	})

	// A managed value that cannot be resolved must not fall back to the
	// install-time flag or to an open socket: the host was meant to be locked
	// down, so the daemon refuses to serve instead.
	t.Run("an unresolvable MDM value is an error", func(t *testing.T) {
		allowGroups = []string{testAllowGroupPrincipal}
		policy := mdm.NewPolicy(map[string]any{mdm.KeyAllowGroups: "no-such-group-08b1f0c4"})

		_, _, err := daemonSocketPrincipals(policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), mdm.KeyAllowGroups)
	})

	// A managed key holding something that is not a list of principals must not
	// read as "no policy set" and quietly hand the decision back to the
	// install-time value.
	t.Run("a malformed MDM value is an error, not a fallback", func(t *testing.T) {
		allowGroups = []string{testAllowGroupPrincipal}

		for name, value := range map[string]any{
			"number": 42,
			"bool":   true,
			"map":    map[string]any{"group": "x"},
		} {
			t.Run(name, func(t *testing.T) {
				policy := mdm.NewPolicy(map[string]any{mdm.KeyAllowGroups: value})

				_, source, err := daemonSocketPrincipals(policy)
				require.Error(t, err)
				assert.Contains(t, source, mdm.KeyAllowGroups, "the managed key must be named as the source that failed")
			})
		}
	})
}

// A TCP listener can express neither a socket mode nor a security descriptor,
// so a restriction configured against one must stop the daemon rather than be
// dropped while it goes on serving every caller that can reach the port.
func TestTCPListenerRefusesARestriction(t *testing.T) {
	t.Run("listenOnAddress refuses before binding", func(t *testing.T) {
		listener, err := listenOnAddress("tcp://127.0.0.1:0", []string{testAllowGroupPrincipal})
		require.Error(t, err)
		require.Nil(t, listener)
		assert.Contains(t, err.Error(), "tcp")
	})

	t.Run("listenOnAddress still serves tcp when nothing is configured", func(t *testing.T) {
		listener, err := listenOnAddress("tcp://127.0.0.1:0", nil)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, listener.Close()) })
		assert.NoError(t, listener.restrict("daemon", nil))
	})

	t.Run("restrict refuses a listener that cannot carry the restriction", func(t *testing.T) {
		listener := &socketListener{network: "tcp", address: "127.0.0.1:41731"}
		require.Error(t, listener.restrict("daemon", []string{testAllowGroupPrincipal}))
		assert.NoError(t, listener.restrict("daemon", nil))
	})

	t.Run("a disabled json socket is not an error", func(t *testing.T) {
		var listener *socketListener
		assert.NoError(t, listener.restrict("daemon JSON", []string{testAllowGroupPrincipal}))
	})
}

// A group name makes the daemon ask a directory service while it is starting.
// That lookup has to be bounded, or an unreachable LDAP or AD backend holds up
// the start until the service manager gives up on it.
func TestResolveAllowGroupsWithin(t *testing.T) {
	t.Run("a resolution that answers in time is passed through", func(t *testing.T) {
		resolved, err := resolveAllowGroupsWithin([]string{"anything"}, time.Minute,
			func([]string) ([]string, error) { return []string{testAllowGroupPrincipal}, nil })
		require.NoError(t, err)
		assert.Equal(t, []string{testAllowGroupPrincipal}, resolved)
	})

	t.Run("a resolution error is passed through", func(t *testing.T) {
		_, err := resolveAllowGroupsWithin([]string{"anything"}, time.Minute,
			func([]string) ([]string, error) { return nil, assert.AnError })
		require.ErrorIs(t, err, assert.AnError)
	})

	// The daemon must stop waiting and refuse to serve, which is the same
	// answer a failed resolution gets: a restriction it cannot evaluate must
	// never become a socket open to everybody.
	t.Run("a lookup that never answers is an error, not an empty restriction", func(t *testing.T) {
		blocked := make(chan struct{})
		t.Cleanup(func() { close(blocked) })

		resolved, err := resolveAllowGroupsWithin([]string{"netbird-users"}, 10*time.Millisecond,
			func([]string) ([]string, error) {
				<-blocked
				return nil, nil
			})
		require.Error(t, err)
		assert.Empty(t, resolved, "a timeout must not yield an unrestricted socket")
		assert.Contains(t, err.Error(), "gid:<id>", "the error should say how to avoid the lookup")
	})
}

func TestTypedPrincipal(t *testing.T) {
	t.Run("a value with no kind is a name to look up", func(t *testing.T) {
		for _, value := range []string{"netbird-users", `NETBIRD\Users`, "1000"} {
			_, typed, err := typedPrincipal(value, ipcauth.KindGID)
			require.NoError(t, err, value)
			assert.False(t, typed, "%q carries no kind", value)
		}
	})

	t.Run("a value of the wanted kind is parsed", func(t *testing.T) {
		principal, typed, err := typedPrincipal("gid:1000", ipcauth.KindGID)
		require.NoError(t, err)
		assert.True(t, typed)
		assert.Equal(t, ipcauth.KindGID, principal.Kind)
		assert.Equal(t, "1000", principal.Value)
	})

	t.Run("a kind for another platform is an error, not a name", func(t *testing.T) {
		_, _, err := typedPrincipal("sid:S-1-5-32-544", ipcauth.KindGID)
		require.Error(t, err)
	})

	t.Run("an unknown kind is an error, not a name", func(t *testing.T) {
		for _, value := range []string{"user:alice", "gid:"} {
			_, _, err := typedPrincipal(value, ipcauth.KindGID)
			require.Error(t, err, value)
		}
	})
}

func TestPrincipalOfKind(t *testing.T) {
	principal, err := principalOfKind("gid:1000", ipcauth.KindGID)
	require.NoError(t, err)
	assert.Equal(t, "1000", principal.Value)

	_, err = principalOfKind("sid:S-1-5-32-544", ipcauth.KindGID)
	assert.Error(t, err, "a principal of another kind must not be read as this one")

	_, err = principalOfKind("1000", ipcauth.KindGID)
	assert.Error(t, err, "an untyped value is not a principal")

	_, err = principalOfKind("gid:", ipcauth.KindGID)
	assert.Error(t, err, "an empty value is not a principal")
}
