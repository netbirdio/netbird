//go:build !android && !ios && !freebsd && !js

package preferences

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/ui/i18n"
)

func ptr[T any](v T) *T { return &v }

func newMDMDefaultsStore(t *testing.T) *Store {
	t.Helper()
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true, "it": true, "de": true}}, nil)
	require.NoError(t, err)
	return s
}

// A proposed default is applied once; a user change afterwards sticks until
// the admin proposes a different value.
func TestApplyMDMDefaults_AppliedOnceThenUserWins(t *testing.T) {
	s := newMDMDefaultsStore(t)
	proposal := MDMDefaults{Language: ptr(i18n.LanguageCode("it")), ViewMode: ptr(ViewModeAdvanced), Theme: ptr(ThemeDark)}

	require.NoError(t, s.ApplyMDMDefaults(proposal))
	got := s.Get()
	assert.Equal(t, i18n.LanguageCode("it"), got.Language, "the proposed language is applied")
	assert.Equal(t, ViewModeAdvanced, got.ViewMode, "the proposed view mode is applied")
	assert.Equal(t, ThemeDark, got.Theme, "the proposed theme is applied")

	require.NoError(t, s.SetLanguage("en"))
	require.NoError(t, s.ApplyMDMDefaults(proposal))
	assert.Equal(t, i18n.LanguageCode("en"), s.Get().Language, "the same proposal must not undo the user's choice")

	require.NoError(t, s.ApplyMDMDefaults(MDMDefaults{Language: ptr(i18n.LanguageCode("de"))}))
	assert.Equal(t, i18n.LanguageCode("de"), s.Get().Language, "a changed proposal is applied again")
}

// Removing a proposal forgets it, so proposing the same value again applies it.
func TestApplyMDMDefaults_RemovedThenProposedAgain(t *testing.T) {
	s := newMDMDefaultsStore(t)
	proposal := MDMDefaults{Theme: ptr(ThemeDark)}

	require.NoError(t, s.ApplyMDMDefaults(proposal))
	require.NoError(t, s.SetTheme(ThemeLight))
	require.NoError(t, s.ApplyMDMDefaults(MDMDefaults{}))
	assert.Equal(t, ThemeLight, s.Get().Theme, "removing the proposal leaves the user's value")

	require.NoError(t, s.ApplyMDMDefaults(proposal))
	assert.Equal(t, ThemeDark, s.Get().Theme, "a proposal that reappears is applied again")
}

func TestApplyMDMDefaults_InvalidValueIgnored(t *testing.T) {
	s := newMDMDefaultsStore(t)
	before := s.Get()

	require.NoError(t, s.ApplyMDMDefaults(MDMDefaults{
		Language: ptr(i18n.LanguageCode("xx")),
		ViewMode: ptr(ViewMode("expert")),
		Theme:    ptr(Theme("neon")),
	}))
	got := s.Get()
	assert.Equal(t, before.Language, got.Language, "an unsupported language is ignored")
	assert.Equal(t, before.ViewMode, got.ViewMode, "an unsupported view mode is ignored")
	assert.Equal(t, before.Theme, got.Theme, "an unsupported theme is ignored")
}

// The record of applied proposals survives a restart, so a restart with the
// same policy does not undo the user's choice.
func TestApplyMDMDefaults_SurvivesRestart(t *testing.T) {
	s := newMDMDefaultsStore(t)
	proposal := MDMDefaults{Language: ptr(i18n.LanguageCode("it"))}
	require.NoError(t, s.ApplyMDMDefaults(proposal))
	require.NoError(t, s.SetLanguage("en"))

	reloaded, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true, "it": true}}, nil)
	require.NoError(t, err)
	require.NoError(t, reloaded.ApplyMDMDefaults(proposal))
	assert.Equal(t, i18n.LanguageCode("en"), reloaded.Get().Language, "the user's choice survives a restart under the same policy")
}

func TestGetReturnsIndependentMDMDefaults(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{}, nil)
	require.NoError(t, err)
	mode := ViewModeAdvanced
	require.NoError(t, s.ApplyMDMDefaults(MDMDefaults{ViewMode: &mode}))

	snapshot := s.Get()
	for k := range snapshot.MDMDefaults {
		snapshot.MDMDefaults[k] = "tampered"
	}

	assert.Equal(t, string(ViewModeAdvanced), s.Get().MDMDefaults[mdmDefaultViewMode],
		"changing a snapshot must not change the store")
}
