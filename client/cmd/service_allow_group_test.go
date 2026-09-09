//go:build !ios && !android

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestCutKind(t *testing.T) {
	tests := []struct {
		value string
		kind  string
		rest  string
		ok    bool
	}{
		{value: "gid:1000", kind: "gid", rest: "1000", ok: true},
		{value: "sid:S-1-5-32-544", kind: "sid", rest: "S-1-5-32-544", ok: true},
		{value: "netbird-users", rest: "netbird-users"},
		{value: "S-1-5-32-544", rest: "S-1-5-32-544"},
		{value: `NETBIRD\Users`, rest: `NETBIRD\Users`},
		// A kind with no value is not a kind: it must not be mistaken for one
		// and accepted as an empty principal.
		{value: "gid:", rest: "gid:"},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			kind, rest, ok := cutKind(tc.value)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.kind, kind)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestPrincipalValue(t *testing.T) {
	value, ok := principalValue("gid:1000", allowGroupKindGID)
	assert.True(t, ok)
	assert.Equal(t, "1000", value)

	_, ok = principalValue("sid:S-1-5-32-544", allowGroupKindGID)
	assert.False(t, ok, "a principal of another kind must not be read as this one")

	_, ok = principalValue("1000", allowGroupKindGID)
	assert.False(t, ok, "an untyped value is not a principal")

	_, ok = principalValue("gid:", allowGroupKindGID)
	assert.False(t, ok, "an empty value is not a principal")
}
