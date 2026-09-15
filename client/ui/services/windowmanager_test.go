//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ownersOf(hidden []hiddenWindow) []string {
	owners := make([]string, 0, len(hidden))
	for _, h := range hidden {
		owners = append(owners, h.owner)
	}
	return owners
}

func TestRestoreHiddenWindowsLockedOnlyReleasesItsOwn(t *testing.T) {
	s := &WindowManager{
		hiddenWindows: []hiddenWindow{
			{owner: "browser-login"},
			{owner: "install-progress"},
			{owner: "browser-login"},
		},
	}

	s.restoreHiddenWindowsLocked("install-progress")
	assert.Equal(t, []string{"browser-login", "browser-login"}, ownersOf(s.hiddenWindows))

	s.restoreHiddenWindowsLocked("browser-login")
	assert.Empty(t, s.hiddenWindows)
}

func TestRestoreHiddenWindowsLockedUnknownOwnerKeepsEverything(t *testing.T) {
	s := &WindowManager{
		hiddenWindows: []hiddenWindow{{owner: "browser-login"}},
	}

	s.restoreHiddenWindowsLocked("welcome")
	assert.Equal(t, []string{"browser-login"}, ownersOf(s.hiddenWindows))
}

func TestRestoreHiddenWindowsLockedEmptyIsNoop(t *testing.T) {
	s := &WindowManager{}
	require.NotPanics(t, func() { s.restoreHiddenWindowsLocked("browser-login") })
	assert.Empty(t, s.hiddenWindows)
}

func TestStampGenerationTracksLatestPerWindow(t *testing.T) {
	s := &WindowManager{generation: map[string]uint64{}}

	first := s.stampGeneration("browser-login", "/#/dialog/browser-login")
	assert.Equal(t, "/#/dialog/browser-login?gen=1", first)
	assert.True(t, s.matchesGeneration("browser-login", 1))

	second := s.stampGeneration("browser-login", "/#/dialog/browser-login?uri=x")
	assert.Equal(t, "/#/dialog/browser-login?uri=x&gen=2", second)
	assert.False(t, s.matchesGeneration("browser-login", 1))
	assert.True(t, s.matchesGeneration("browser-login", 2))
}

func TestMatchesGenerationUntrackedWindowAccepts(t *testing.T) {
	s := &WindowManager{generation: map[string]uint64{}}
	assert.True(t, s.matchesGeneration("main", 0))
}

func TestPaintedGeneration(t *testing.T) {
	tests := []struct {
		name string
		data any
		want uint64
	}{
		{"string", "7", 7},
		{"float", float64(7), 7},
		{"slice", []any{"7"}, 7},
		{"empty slice", []any{}, 0},
		{"unparsable", "abc", 0},
		{"nil", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, paintedGeneration(tc.data))
		})
	}
}
