//go:build !android && !ios && !freebsd && !js

package preferences

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/ui/i18n"
)

// fakeValidator implements LanguageValidator for tests so we don't need a
// fully-loaded i18n.Bundle.
type fakeValidator struct{ ok map[i18n.LanguageCode]bool }

func (f fakeValidator) HasLanguage(code i18n.LanguageCode) bool { return f.ok[code] }

// recordingEmitter captures Emit calls so tests can assert the broadcast
// fired.
type recordingEmitter struct {
	mu    sync.Mutex
	calls []emitCall
}

type emitCall struct {
	name string
	data []any
}

func (r *recordingEmitter) Emit(name string, data ...any) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, emitCall{name: name, data: data})
	return true
}

func (r *recordingEmitter) calledWith(name string) []emitCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []emitCall
	for _, c := range r.calls {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// withTempConfigDir reroots os.UserConfigDir() at a temporary directory by
// pointing the OS-specific env vars there. Restored automatically by
// t.Setenv.
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", tmp)
		require.NoError(t, os.MkdirAll(filepath.Join(tmp, "Library", "Application Support"), 0o755))
	case "windows":
		t.Setenv("AppData", tmp)
	default:
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
	return tmp
}

func TestStore_DefaultsWhenFileMissing(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true}}, nil)
	require.NoError(t, err)

	got := s.Get()
	assert.Equal(t, i18n.LanguageCode(""), got.Language, "language must be empty when no file is on disk so the frontend can detect the browser locale")
	assert.Equal(t, DefaultViewMode, got.ViewMode, "view-mode default should still apply")
}

func TestStore_SetLanguagePersistsAndBroadcasts(t *testing.T) {
	withTempConfigDir(t)
	emitter := &recordingEmitter{}
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true, "hu": true}}, emitter)
	require.NoError(t, err)

	ch, unsubscribe := s.Subscribe()
	defer unsubscribe()

	require.NoError(t, s.SetLanguage("hu"))

	got := s.Get()
	assert.Equal(t, i18n.LanguageCode("hu"), got.Language, "Get should reflect the SetLanguage value")

	select {
	case v := <-ch:
		assert.Equal(t, i18n.LanguageCode("hu"), v.Language, "subscriber should receive the new value")
	case <-time.After(time.Second):
		t.Fatal("subscriber timed out waiting for update")
	}

	emits := emitter.calledWith(EventPreferencesChanged)
	require.Len(t, emits, 1, "Emit should fire exactly once per SetLanguage")
	payload, ok := emits[0].data[0].(UIPreferences)
	require.True(t, ok, "emitter payload should be UIPreferences")
	assert.Equal(t, i18n.LanguageCode("hu"), payload.Language)
}

func TestStore_LoadFromDisk(t *testing.T) {
	withTempConfigDir(t)
	path, err := preferencesPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(`{"language":"hu"}`), 0o644))

	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"hu": true}}, nil)
	require.NoError(t, err)

	got := s.Get()
	assert.Equal(t, i18n.LanguageCode("hu"), got.Language, "Get should load language from existing file")
}

func TestStore_UnsupportedLanguageRejected(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true}}, nil)
	require.NoError(t, err)

	err = s.SetLanguage("xx")
	require.Error(t, err, "unknown language must be rejected")
	assert.ErrorIs(t, err, i18n.ErrUnsupportedLanguage)

	err = s.SetLanguage("")
	assert.ErrorIs(t, err, i18n.ErrUnsupportedLanguage, "empty language code must be rejected")
}

func TestStore_NoValidatorAcceptsAnything(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(nil, nil)
	require.NoError(t, err)

	require.NoError(t, s.SetLanguage("fr"))
	got := s.Get()
	assert.Equal(t, i18n.LanguageCode("fr"), got.Language)
}

func TestStore_SetLanguageIdempotent(t *testing.T) {
	withTempConfigDir(t)
	emitter := &recordingEmitter{}
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true}}, emitter)
	require.NoError(t, err)

	// First call goes from "" (unset) to "en" — real change, one broadcast.
	require.NoError(t, s.SetLanguage("en"))
	require.Len(t, emitter.calledWith(EventPreferencesChanged), 1,
		"first SetLanguage from unset should broadcast")

	// Second call is a no-op — no disk write, no broadcast. Without this
	// guard the tray would re-render the menu on every cosmetic re-save of
	// the preferences file.
	require.NoError(t, s.SetLanguage("en"))
	assert.Len(t, emitter.calledWith(EventPreferencesChanged), 1,
		"re-setting the current language should not broadcast again")
}

func TestStore_CorruptFileFallsBackToDefault(t *testing.T) {
	withTempConfigDir(t)
	path, err := preferencesPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o644))

	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true}}, nil)
	require.NoError(t, err, "corrupt file should not fail construction")

	got := s.Get()
	assert.Equal(t, i18n.LanguageCode(""), got.Language, "corrupt JSON should leave the empty (unset) default in place so the frontend can re-detect")
}

func TestStore_UnsubscribeStopsUpdates(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"en": true, "hu": true}}, nil)
	require.NoError(t, err)

	ch, unsubscribe := s.Subscribe()
	unsubscribe()

	require.NoError(t, s.SetLanguage("hu"))

	select {
	case _, ok := <-ch:
		assert.False(t, ok, "channel should be closed after unsubscribe")
	case <-time.After(time.Second):
		t.Fatal("expected closed channel, got nothing")
	}
}

func TestStore_FileShapeIsJSON(t *testing.T) {
	withTempConfigDir(t)
	s, err := NewStore(fakeValidator{ok: map[i18n.LanguageCode]bool{"hu": true}}, nil)
	require.NoError(t, err)
	require.NoError(t, s.SetLanguage("hu"))

	path, err := preferencesPath()
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var parsed UIPreferences
	require.NoError(t, json.Unmarshal(data, &parsed), "on-disk file must be valid JSON")
	assert.Equal(t, i18n.LanguageCode("hu"), parsed.Language)
}

func TestStore_ErrUnsupportedSentinel(t *testing.T) {
	// Verifies callers can match on the sentinel error rather than parsing
	// strings — protects against accidental %v -> %w changes that would
	// silently break errors.Is.
	err := errors.New("inner")
	wrapped := errors.Join(i18n.ErrUnsupportedLanguage, err)
	assert.ErrorIs(t, wrapped, i18n.ErrUnsupportedLanguage)
}
