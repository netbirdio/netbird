//go:build !android && !ios && !freebsd && !js

// Package preferences holds user-scope UI state that is independent of the
// daemon profile: language, and any future toggles the React UI exposes to
// the user. The Store reads from and writes to a JSON file under
// os.UserConfigDir(), validates input against an injected language
// validator (typically *i18n.Bundle), and broadcasts changes to in-process
// subscribers (tray) plus an optional Wails emitter (frontend).
//
// No Wails dependency — the emitter is consumed through a minimal
// interface so the package can be tested without spinning up Wails.
package preferences

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/util"
)

// preferencesFileName is the JSON file holding user-scope UI preferences.
// Stored under os.UserConfigDir()/netbird so it lives in the OS-user's
// writable config dir, not the daemon's root-owned state. Per-OS-user,
// shared across all daemon profiles.
const preferencesFileName = "ui-preferences.json"

// EventPreferencesChanged fires whenever the on-disk preferences are
// updated (from any source). The payload is the fresh UIPreferences value.
// Wails registers this name in init() so the React frontend can subscribe.
const EventPreferencesChanged = "netbird:preferences:changed"

// UIPreferences is the user-scope UI state mirrored to disk and to the
// frontend. Pointer-free because the whole document is rewritten on every
// change — there are no per-field partial updates.
type UIPreferences struct {
	Language i18n.LanguageCode `json:"language"`
}

// LanguageValidator is the dependency Store needs to reject SetLanguage
// inputs that have no shipped bundle. *i18n.Bundle satisfies it directly.
type LanguageValidator interface {
	HasLanguage(code i18n.LanguageCode) bool
}

// Emitter is the dependency Store needs to broadcast changes to the
// frontend. *application.EventProcessor (Wails) satisfies it; tests pass
// nil or a fake.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// Store is the user-scope UI preferences store. Read at app start,
// updated by the React settings page (via the Wails-bound facade), and
// observed by the tray which re-renders its menu in the new language.
type Store struct {
	path string

	mu      sync.RWMutex
	current UIPreferences

	subsMu sync.Mutex
	subs   []chan UIPreferences

	validator LanguageValidator
	emitter   Emitter
}

// NewStore loads preferences from disk (creating a default file when
// none exists). The validator is consulted on SetLanguage; pass nil to
// skip validation (used by the unit tests). The emitter is optional —
// when set, SetLanguage broadcasts EventPreferencesChanged.
func NewStore(validator LanguageValidator, emitter Emitter) (*Store, error) {
	path, err := preferencesPath()
	if err != nil {
		return nil, fmt.Errorf("resolve preferences path: %w", err)
	}

	s := &Store{
		path:      path,
		validator: validator,
		emitter:   emitter,
		current:   UIPreferences{Language: i18n.DefaultLanguage},
	}

	if err := s.load(); err != nil {
		log.Warnf("load ui preferences from %s: %v (using defaults)", path, err)
	}

	return s, nil
}

// Get returns a copy of the current preferences.
func (s *Store) Get() UIPreferences {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// SetLanguage validates and persists a new language preference, then
// broadcasts the change to internal subscribers (tray) and the emitter
// (frontend).
func (s *Store) SetLanguage(lang i18n.LanguageCode) error {
	if lang == "" {
		return fmt.Errorf("%w: empty code", i18n.ErrUnsupportedLanguage)
	}
	if s.validator != nil && !s.validator.HasLanguage(lang) {
		return fmt.Errorf("%w: %q", i18n.ErrUnsupportedLanguage, lang)
	}

	s.mu.Lock()
	if s.current.Language == lang {
		s.mu.Unlock()
		return nil
	}
	next := s.current
	next.Language = lang
	if err := s.persistLocked(next); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist preferences: %w", err)
	}
	s.current = next
	s.mu.Unlock()

	s.broadcast(next)
	return nil
}

// Subscribe returns a channel that receives every persisted change. The
// unsubscribe function closes the channel and removes it from the list;
// callers must not close the channel themselves.
func (s *Store) Subscribe() (<-chan UIPreferences, func()) {
	ch := make(chan UIPreferences, 4)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()

	unsubscribe := func() {
		s.subsMu.Lock()
		defer s.subsMu.Unlock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, unsubscribe
}

// load reads the on-disk file into current. A missing file is not an
// error (we keep the in-memory default); malformed contents are reported
// so the caller can log+continue with the default.
func (s *Store) load() error {
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	var loaded UIPreferences
	if _, err := util.ReadJson(s.path, &loaded); err != nil {
		return err
	}

	if loaded.Language == "" {
		loaded.Language = i18n.DefaultLanguage
	}

	s.mu.Lock()
	s.current = loaded
	s.mu.Unlock()
	return nil
}

// persistLocked writes the candidate preferences atomically. Caller must
// hold s.mu (write lock); the lock is not released here so the in-memory
// state is updated only after a successful write.
func (s *Store) persistLocked(v UIPreferences) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(s.path), err)
	}
	return util.WriteJson(context.Background(), s.path, v)
}

// broadcast fans the new value out to internal subscribers and to the
// frontend emitter. Subscribers with a full buffer are skipped — the tray
// only cares about the latest value, so dropping intermediate frames
// during a burst is safe.
func (s *Store) broadcast(v UIPreferences) {
	s.subsMu.Lock()
	subs := make([]chan UIPreferences, len(s.subs))
	copy(subs, s.subs)
	s.subsMu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- v:
		default:
			log.Debugf("preferences subscriber channel full; dropping update")
		}
	}

	if s.emitter != nil {
		s.emitter.Emit(EventPreferencesChanged, v)
	}
}

// preferencesPath resolves os.UserConfigDir()/netbird/ui-preferences.json.
func preferencesPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netbird", preferencesFileName), nil
}
