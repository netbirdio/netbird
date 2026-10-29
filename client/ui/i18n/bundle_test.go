//go:build !android && !ios && !freebsd && !js

package i18n

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLocales returns an in-memory FS that mirrors the real
// client/ui/i18n/locales layout (root-level _index.json plus
// <code>/common.json bundles). Used by every Bundle test so we don't
// depend on the embedded production bundles staying stable.
func fakeLocales() fstest.MapFS {
	return fstest.MapFS{
		"_index.json": {Data: []byte(`{
            "languages": [
                {"code": "en", "displayName": "English", "englishName": "English"},
                {"code": "hu", "displayName": "Magyar", "englishName": "Hungarian"}
            ]
        }`)},
		"en/common.json": {Data: []byte(`{
            "tray.menu.connect": {"message": "Connect", "description": "Tray menu item"},
            "tray.menu.installVersion": {"message": "Install version {version}"},
            "notify.update.body": {"message": "NetBird {version} is available."}
        }`)},
		"hu/common.json": {Data: []byte(`{
            "tray.menu.connect": {"message": "Csatlakozás"},
            "tray.menu.installVersion": {"message": "{version} telepítése"}
        }`)},
	}
}

func TestBundle_LoadsAllLanguages(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	langs := b.Languages()
	require.Len(t, langs, 2)
	codes := []LanguageCode{langs[0].Code, langs[1].Code}
	assert.ElementsMatch(t, []LanguageCode{"en", "hu"}, codes, "Languages should list every bundle that loaded")
}

func TestBundle_TranslateLooksUpKey(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	assert.Equal(t, "Csatlakozás", b.Translate("hu", "tray.menu.connect"))
	assert.Equal(t, "Connect", b.Translate("en", "tray.menu.connect"))
}

func TestBundle_TranslateSubstitutesPlaceholders(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	assert.Equal(t, "Install version 1.2.3",
		b.Translate("en", "tray.menu.installVersion", "version", "1.2.3"),
		"placeholders should substitute by name")
	assert.Equal(t, "1.2.3 telepítése",
		b.Translate("hu", "tray.menu.installVersion", "version", "1.2.3"))
}

func TestBundle_TranslateFallsBackToEnglish(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	// notify.update.body is missing from the hu bundle; English fallback
	// applies so the user always sees a populated label rather than the
	// raw key.
	got := b.Translate("hu", "notify.update.body", "version", "9.9.9")
	assert.Equal(t, "NetBird 9.9.9 is available.", got, "missing hu key should fall back to en bundle")
}

func TestBundle_TranslateUnknownKeyReturnsKey(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	assert.Equal(t, "tray.missing", b.Translate("en", "tray.missing"),
		"unknown key should return the key itself for debugability")
}

func TestBundle_BundleForReturnsCopy(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	m, err := b.BundleFor("en")
	require.NoError(t, err)
	require.NotEmpty(t, m, "BundleFor should return populated map for known language")

	m["tray.menu.connect"] = "Mutated"
	assert.Equal(t, "Connect", b.Translate("en", "tray.menu.connect"),
		"BundleFor must return a copy, not the live map")
}

func TestBundle_BundleForUnknownLanguage(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	_, err = b.BundleFor("xx")
	assert.ErrorIs(t, err, ErrUnsupportedLanguage)
}

func TestBundle_HasLanguage(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	assert.True(t, b.HasLanguage("en"))
	assert.True(t, b.HasLanguage("hu"))
	assert.False(t, b.HasLanguage("de"))
}

func TestBundle_MissingDefaultBundleFails(t *testing.T) {
	// Without an en bundle we have nothing to fall back to, so construction
	// must hard-fail. Catches packaging accidents where someone drops the
	// English locale.
	fs := fstest.MapFS{
		"_index.json":    {Data: []byte(`{"languages":[{"code":"hu","displayName":"Magyar","englishName":"Hungarian"}]}`)},
		"hu/common.json": {Data: []byte(`{"k":{"message":"v"}}`)},
	}
	_, err := NewBundle(fs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default language")
}

func TestBundle_MissingBundleSkipsLanguage(t *testing.T) {
	// A language declared in the index but missing its bundle file is
	// dropped from Languages with a warning — adding a new language must
	// be a two-step process (declare + ship), not declare-only.
	fs := fstest.MapFS{
		"_index.json": {Data: []byte(`{"languages":[
            {"code":"en","displayName":"English","englishName":"English"},
            {"code":"de","displayName":"Deutsch","englishName":"German"}
        ]}`)},
		"en/common.json": {Data: []byte(`{"k":{"message":"v"}}`)},
	}
	b, err := NewBundle(fs)
	require.NoError(t, err)

	langs := b.Languages()
	require.Len(t, langs, 1)
	assert.Equal(t, LanguageCode("en"), langs[0].Code, "language without a bundle file must be dropped")
	assert.False(t, b.HasLanguage("de"))
}

func TestBundle_OddPlaceholderArgsDoNotPanic(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	// Trailing dangling arg should be dropped, not panic — preserves UI
	// stability when a caller passes an unpaired placeholder by mistake.
	got := b.Translate("en", "tray.menu.installVersion", "version", "1.2.3", "extra")
	assert.Equal(t, "Install version 1.2.3", got)
}
