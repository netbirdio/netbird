//go:build !android && !ios && !freebsd && !js

package i18n

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

// shippedBundle loads the real locale tree rather than the fstest fixture the
// other tests use: these checks exist to catch a key the daemon publishes but no
// bundle translates, which only the shipped files can prove.
func shippedBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := NewBundle(os.DirFS("locales"))
	require.NoError(t, err, "the shipped locale tree must load")
	return b
}

// The daemon publishes a message key and each UI resolves it locally, so a key
// with no en entry degrades to the daemon's English fallback and silently stops
// being translatable. Fail the build instead.
func TestUserMessageKeysExistInEnglishBundle(t *testing.T) {
	b := shippedBundle(t)

	for key, text := range proto.UserMessageTexts {
		got, ok := b.Lookup(DefaultLanguage, string(key))
		if !assert.True(t, ok, "message key %q has no en translation", key) {
			continue
		}
		assert.Equal(t, text, got,
			"en translation of %q must match the daemon's English fallback", key)
	}
}

func TestUserMessageTitleKeysExistInEnglishBundle(t *testing.T) {
	b := shippedBundle(t)

	for _, key := range proto.UserMessageTitleKeys {
		_, ok := b.Lookup(DefaultLanguage, string(key))
		assert.True(t, ok, "title key %q has no en translation", key)
	}
}

// Every shipped locale must translate the daemon's keys, not just en. A missing
// one still renders (Lookup falls back to en) but the notification would show up
// in English for that user, which is the bug this whole mechanism exists to fix.
func TestUserMessageKeysTranslatedInEveryLanguage(t *testing.T) {
	b := shippedBundle(t)

	keys := make([]proto.UserMessageKey, 0, len(proto.UserMessageTexts))
	for key := range proto.UserMessageTexts {
		keys = append(keys, key)
	}
	keys = append(keys, proto.UserMessageTitleKeys...)

	for _, lang := range b.Languages() {
		bundle, err := b.BundleFor(lang.Code)
		require.NoError(t, err, "BundleFor(%q)", lang.Code)

		for _, key := range keys {
			text, ok := bundle[string(key)]
			if !assert.True(t, ok, "locale %q is missing key %q", lang.Code, key) {
				continue
			}
			assert.NotEmpty(t, text, "locale %q has an empty message for %q", lang.Code, key)
		}
	}
}

// The tray composes a title from these when an event carries no title key, so a
// gap here would render "event.severity.warning: DNS" to the user.
func TestEventTitleKeysTranslatedInEveryLanguage(t *testing.T) {
	b := shippedBundle(t)

	keys := []string{
		"event.title",
		"event.severity.info", "event.severity.warning",
		"event.severity.error", "event.severity.critical",
		"event.category.network", "event.category.dns",
		"event.category.authentication", "event.category.connectivity",
		"event.category.system",
	}

	for _, lang := range b.Languages() {
		bundle, err := b.BundleFor(lang.Code)
		require.NoError(t, err, "BundleFor(%q)", lang.Code)

		for _, key := range keys {
			text, ok := bundle[key]
			if !assert.True(t, ok, "locale %q is missing key %q", lang.Code, key) {
				continue
			}
			assert.NotEmpty(t, text, "locale %q has an empty message for %q", lang.Code, key)
		}
	}

	// The composed title is useless without both slots.
	title, ok := b.Lookup(DefaultLanguage, "event.title", "severity", "Warning", "category", "DNS")
	require.True(t, ok)
	assert.Equal(t, "Warning: DNS", title, "event.title must substitute both placeholders")
}

func TestBundleLookupReportsMisses(t *testing.T) {
	b, err := NewBundle(fakeLocales())
	require.NoError(t, err)

	got, ok := b.Lookup("en", "tray.menu.connect")
	assert.True(t, ok)
	assert.Equal(t, "Connect", got)

	// An absent key must report a miss rather than echo the key, so callers can
	// substitute their own fallback.
	got, ok = b.Lookup("en", "tray.missing")
	assert.False(t, ok, "unknown key must report a miss")
	assert.Empty(t, got, "a miss must not return the key")

	// Empty keys reach Lookup from events that carry no title key at all.
	_, ok = b.Lookup("en", "")
	assert.False(t, ok, "empty key must report a miss")
}
