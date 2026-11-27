//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

func TestMDMDefaultsFrom(t *testing.T) {
	d := mdmDefaultsFrom(mdm.NewPolicy(map[string]any{
		mdm.KeyDefaultLanguage: " it ",
		mdm.KeyDefaultViewMode: "advanced",
		mdm.KeyDefaultTheme:    "dark",
	}))
	require.NotNil(t, d.Language)
	require.NotNil(t, d.ViewMode)
	require.NotNil(t, d.Theme)
	assert.Equal(t, i18n.LanguageCode("it"), *d.Language, "the language is trimmed")
	assert.Equal(t, preferences.ViewModeAdvanced, *d.ViewMode, "view mode")
	assert.Equal(t, preferences.ThemeDark, *d.Theme, "theme")

	empty := mdmDefaultsFrom(mdm.NewPolicy(map[string]any{mdm.KeyMTU: int64(1300)}))
	assert.Nil(t, empty.Language, "no language proposed")
	assert.Nil(t, empty.ViewMode, "no view mode proposed")
	assert.Nil(t, empty.Theme, "no theme proposed")
}
