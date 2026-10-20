//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/mdm"
)

func TestShouldEnableAutostartDefault(t *testing.T) {
	allPass := autostartDefaultState{
		supported:    true,
		mdmDisabled:  false,
		priorInstall: false,
	}

	tests := []struct {
		name       string
		mutate     func(*autostartDefaultState)
		wantEnable bool
		wantReason string
	}{
		{
			name:       "fresh install with all guards passing enables",
			mutate:     func(*autostartDefaultState) {},
			wantEnable: true,
		},
		{
			name:       "unsupported platform skips",
			mutate:     func(s *autostartDefaultState) { s.supported = false },
			wantReason: "autostart not supported on this platform",
		},
		{
			name:       "MDM disable skips",
			mutate:     func(s *autostartDefaultState) { s.mdmDisabled = true },
			wantReason: "autostart disabled by MDM policy",
		},
		{
			name:       "existing installation (upgrade) skips",
			mutate:     func(s *autostartDefaultState) { s.priorInstall = true },
			wantReason: "existing NetBird installation",
		},
		{
			name: "unsupported wins over every other guard",
			mutate: func(s *autostartDefaultState) {
				s.supported = false
				s.mdmDisabled = true
				s.priorInstall = true
			},
			wantReason: "autostart not supported on this platform",
		},
		{
			name: "MDM disable wins over prior install",
			mutate: func(s *autostartDefaultState) {
				s.mdmDisabled = true
				s.priorInstall = true
			},
			wantReason: "autostart disabled by MDM policy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := allPass
			tc.mutate(&state)
			enable, reason := shouldEnableAutostartDefault(state)
			assert.Equal(t, tc.wantEnable, enable, "enable decision should match for state %+v", state)
			assert.Equal(t, tc.wantReason, reason, "skip reason should identify the failing guard")
		})
	}
}

func TestAutostartDisabledByMDM(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]any
		want   bool
	}{
		{
			name:   "empty policy does not disable",
			values: nil,
			want:   false,
		},
		{
			name:   "unrelated managed keys do not disable",
			values: map[string]any{mdm.KeyDisableAutoConnect: true},
			want:   false,
		},
		{
			name:   "disableAutostart true disables",
			values: map[string]any{mdm.KeyDisableAutostart: true},
			want:   true,
		},
		{
			name:   "disableAutostart registry DWORD 1 disables",
			values: map[string]any{mdm.KeyDisableAutostart: int64(1)},
			want:   true,
		},
		{
			name:   "disableAutostart string true disables",
			values: map[string]any{mdm.KeyDisableAutostart: "true"},
			want:   true,
		},
		{
			name:   "disableAutostart explicit false allows",
			values: map[string]any{mdm.KeyDisableAutostart: false},
			want:   false,
		},
		{
			name:   "unparseable managed value is treated as disabled",
			values: map[string]any{mdm.KeyDisableAutostart: "not-a-bool"},
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := autostartDisabledByMDM(mdm.NewPolicy(tc.values))
			assert.Equal(t, tc.want, got, "MDM disable decision should match for values %v", tc.values)
		})
	}
}
