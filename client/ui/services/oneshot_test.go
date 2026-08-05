//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func TestIsPrivilegedSettingsRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no arguments"},
		{name: "double dash", args: []string{"--" + FlagApplyPrivilegedSettings}, want: true},
		{name: "single dash", args: []string{"-" + FlagApplyPrivilegedSettings}, want: true},
		{
			name: "among other flags",
			args: []string{"--daemon-addr", "unix:///tmp/x.sock", "--" + FlagApplyPrivilegedSettings},
			want: true,
		},
		// A marker, not a value: the caller never passes one, and reading a value
		// would mean "--flag=false" started the one-shot too.
		{name: "with a value", args: []string{"--" + FlagApplyPrivilegedSettings + "=true"}},
		{name: "unrelated flags", args: []string{"--log-level", "debug"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPrivilegedSettingsRun(tt.args), "args %v", tt.args)
		})
	}
}

// What SetGuardedSettings renders has to be what the one-shot reads back, for every
// setting in the table. This is the property that keeps the two ends of an allowlist
// from drifting, so it is checked field by field rather than by example.
func TestGuardedFieldsRoundTrip(t *testing.T) {
	on, off := true, false
	tests := []struct {
		name     string
		settings GuardedSettings
		want     func(*testing.T, *proto.SetConfigRequest)
	}{
		{
			name:     "management url",
			settings: GuardedSettings{ManagementURL: "https://mgmt.example.com:33073"},
			want: func(t *testing.T, req *proto.SetConfigRequest) {
				assert.Equal(t, "https://mgmt.example.com:33073", req.GetManagementUrl())
			},
		},
		{
			name:     "ssh server on",
			settings: GuardedSettings{ServerSSHAllowed: &on},
			want: func(t *testing.T, req *proto.SetConfigRequest) {
				require.NotNil(t, req.ServerSSHAllowed)
				assert.True(t, *req.ServerSSHAllowed)
			},
		},
		{
			name:     "ssh root off",
			settings: GuardedSettings{EnableSSHRoot: &off},
			want: func(t *testing.T, req *proto.SetConfigRequest) {
				require.NotNil(t, req.EnableSSHRoot, "an explicit false must survive, not read as absent")
				assert.False(t, *req.EnableSSHRoot)
			},
		},
		{
			name:     "ssh auth off",
			settings: GuardedSettings{DisableSSHAuth: &on},
			want: func(t *testing.T, req *proto.SetConfigRequest) {
				require.NotNil(t, req.DisableSSHAuth)
				assert.True(t, *req.DisableSSHAuth)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := parseRendered(t, tt.settings)
			tt.want(t, req)
		})
	}
}

// A setting nobody asked about must not arrive at the daemon at all: sending its
// zero value would change it.
func TestGuardedFieldsCarryOnlyWhatWasAsked(t *testing.T) {
	on := true
	req := parseRendered(t, GuardedSettings{ProfileName: "work", EnableSSHRoot: &on})

	assert.Equal(t, "work", req.GetProfileName(), "profile")
	require.NotNil(t, req.EnableSSHRoot)
	assert.Nil(t, req.ServerSSHAllowed, "untouched setting")
	assert.Nil(t, req.DisableSSHAuth, "untouched setting")
	assert.Empty(t, req.GetManagementUrl(), "untouched setting")
}

func TestPrivilegedRequestRejectsAnEmptyChange(t *testing.T) {
	_, err := privilegedRequest("default", "vma", make([]fieldValue, len(guardedFields)))
	require.Error(t, err, "nothing to apply is not a request worth sending as root")
}

// A value the table cannot parse is refused rather than guessed at.
func TestPrivilegedRequestRejectsAnUnparseableValue(t *testing.T) {
	values := make([]fieldValue, len(guardedFields))
	for i, field := range guardedFields {
		if field.flag != FlagEnableSSHRoot {
			continue
		}
		require.NoError(t, values[i].Set("perhaps"))
	}

	_, err := privilegedRequest("default", "vma", values)
	require.Error(t, err)
	assert.Contains(t, err.Error(), FlagEnableSSHRoot, "which flag was wrong")
}

// parseRendered puts the settings through both ends: rendered as the arguments the
// elevated process is given, then parsed as that process parses them.
func parseRendered(t *testing.T, p GuardedSettings) *proto.SetConfigRequest {
	t.Helper()

	rendered := guardedSettings(p)
	require.NotEmpty(t, rendered, "nothing rendered for %+v", p)

	values := make([]fieldValue, len(guardedFields))
	for _, setting := range rendered {
		flag, value, found := splitFlag(setting.arg)
		require.True(t, found, "rendered %q without a value", setting.arg)

		matched := false
		for i, field := range guardedFields {
			if field.flag != flag {
				continue
			}
			require.NoError(t, values[i].Set(value))
			matched = true
		}
		require.True(t, matched, "rendered %q, which no field claims", setting.arg)
	}

	req, err := privilegedRequest(p.ProfileName, p.Username, values)
	require.NoError(t, err)
	return req
}

// splitFlag takes "--name=value" apart the way the flag package does.
func splitFlag(arg string) (name, value string, found bool) {
	trimmed := arg
	for len(trimmed) > 0 && trimmed[0] == '-' {
		trimmed = trimmed[1:]
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '=' {
			return trimmed[:i], trimmed[i+1:], true
		}
	}
	return trimmed, "", false
}
