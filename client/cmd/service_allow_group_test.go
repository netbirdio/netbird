//go:build !ios && !android

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
