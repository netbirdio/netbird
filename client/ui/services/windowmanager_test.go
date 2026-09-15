//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v3/pkg/application"
)

type fakeWindow struct {
	name    string
	visible bool
	shown   int
	hidden  int
}

func newFakeWindow(name string) *fakeWindow {
	return &fakeWindow{name: name, visible: true}
}

func (f *fakeWindow) Show() application.Window {
	f.visible = true
	f.shown++
	return nil
}

func (f *fakeWindow) Hide() application.Window {
	f.visible = false
	f.hidden++
	return nil
}

func (f *fakeWindow) IsVisible() bool { return f.visible }

func (f *fakeWindow) Name() string { return f.name }

func newTestWindowManager(windows ...*fakeWindow) (*WindowManager, *int) {
	raised := 0
	s := &WindowManager{
		generation: map[string]uint64{},
		allWindows: func() []hideableWindow {
			all := make([]hideableWindow, 0, len(windows))
			for _, w := range windows {
				all = append(all, w)
			}
			return all
		},
		raiseMain: func() { raised++ },
	}
	return s, &raised
}

func ownersOf(hidden []hiddenWindow) []string {
	owners := make([]string, 0, len(hidden))
	for _, h := range hidden {
		owners = append(owners, h.owner)
	}
	return owners
}

func TestHideOtherWindowsLockedSkipsKeepNameAndInvisible(t *testing.T) {
	main := newFakeWindow("main")
	settings := newFakeWindow("settings")
	settings.visible = false
	popup := newFakeWindow("browser-login")
	s, _ := newTestWindowManager(main, settings, popup)

	s.hideOtherWindowsLocked("browser-login")

	assert.False(t, main.visible)
	assert.Equal(t, 1, main.hidden)
	assert.Equal(t, 0, settings.hidden, "an already hidden window must not be recorded")
	assert.Equal(t, 0, popup.hidden, "the popup itself must stay visible")
	assert.Equal(t, []string{"browser-login"}, ownersOf(s.hiddenWindows))
}

func TestInstallDuringLoginKeepsMainHiddenUntilLoginCloses(t *testing.T) {
	main := newFakeWindow("main")
	login := newFakeWindow("browser-login")
	install := newFakeWindow("install-progress")
	s, raised := newTestWindowManager(main, login, install)

	s.hideOtherWindowsLocked("browser-login")
	require.False(t, main.visible)
	require.False(t, install.visible)

	install.visible = true
	s.hideOtherWindowsLocked("install-progress")
	assert.False(t, login.visible, "the login popup is hidden by the install popup")

	s.restoreHiddenWindowsLocked("install-progress")
	assert.True(t, login.visible, "the install popup restores the login popup it hid")
	assert.False(t, main.visible, "the main window stays hidden for the login popup")
	assert.Equal(t, 0, *raised)
	assert.Equal(t, []string{"browser-login", "browser-login"}, ownersOf(s.hiddenWindows))

	s.restoreHiddenWindowsLocked("browser-login")
	assert.True(t, main.visible)
	assert.Equal(t, 1, *raised, "restoring the main window raises it above the SSO browser")
	assert.Empty(t, s.hiddenWindows)
}

func TestRestoreHiddenWindowsLockedUnknownOwnerKeepsEverything(t *testing.T) {
	main := newFakeWindow("main")
	s, raised := newTestWindowManager(main)
	s.hideOtherWindowsLocked("browser-login")

	s.restoreHiddenWindowsLocked("welcome")

	assert.False(t, main.visible)
	assert.Equal(t, []string{"browser-login"}, ownersOf(s.hiddenWindows))
	assert.Equal(t, 0, *raised)
}

func TestRestoreHiddenWindowsLockedWithoutMainDoesNotRaise(t *testing.T) {
	settings := newFakeWindow("settings")
	s, raised := newTestWindowManager(settings)
	s.hideOtherWindowsLocked("browser-login")

	s.restoreHiddenWindowsLocked("browser-login")

	assert.True(t, settings.visible)
	assert.Equal(t, 0, *raised)
}

func TestRestoreHiddenWindowsLockedEmptyIsNoop(t *testing.T) {
	s, _ := newTestWindowManager()
	require.NotPanics(t, func() { s.restoreHiddenWindowsLocked("browser-login") })
	assert.Empty(t, s.hiddenWindows)
}

func TestStampGenerationTracksLatestPerWindow(t *testing.T) {
	s, _ := newTestWindowManager()

	first := s.stampGeneration("browser-login", "/#/dialog/browser-login")
	assert.Equal(t, "/#/dialog/browser-login?gen=1", first)
	assert.True(t, s.matchesGeneration("browser-login", 1))

	second := s.stampGeneration("browser-login", "/#/dialog/browser-login?uri=x")
	assert.Equal(t, "/#/dialog/browser-login?uri=x&gen=2", second)
	assert.False(t, s.matchesGeneration("browser-login", 1))
	assert.True(t, s.matchesGeneration("browser-login", 2))
}

func TestMatchesGenerationUntrackedWindowAccepts(t *testing.T) {
	s, _ := newTestWindowManager()
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
