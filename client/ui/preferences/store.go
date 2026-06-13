//go:build !android && !ios && !freebsd && !js

// Package preferences holds user-scope UI state, independent of the daemon
// profile and shared across all profiles. The Store persists to JSON under
// os.UserConfigDir() and broadcasts changes to in-process subscribers plus an
// optional emitter.
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

// Lives under os.UserConfigDir()/netbird (OS-user writable, not the daemon's
// root-owned state).
const preferencesFileName = "ui-preferences.json"

// EventPreferencesChanged fires on every persisted update, payload UIPreferences.
const EventPreferencesChanged = "netbird:preferences:changed"

// ViewMode is the preferred Main-window layout: "default" (compact, 380-wide)
// or "advanced" (900-wide).
type ViewMode string

const (
	ViewModeDefault  ViewMode = "default"
	ViewModeAdvanced ViewMode = "advanced"
)

// DefaultViewMode applies when no file exists or its view-mode is empty.
const DefaultViewMode = ViewModeDefault

var ErrUnsupportedViewMode = errors.New("unsupported view mode")

func (v ViewMode) IsValid() bool {
	switch v {
	case ViewModeDefault, ViewModeAdvanced:
		return true
	}
	return false
}

// UIPreferences is rewritten in full on every change; there are no partial updates.
type UIPreferences struct {
	Language            i18n.LanguageCode `json:"language"`
	ViewMode            ViewMode          `json:"viewMode"`
	OnboardingCompleted bool              `json:"onboardingCompleted"`
}

// LanguageValidator rejects SetLanguage inputs with no shipped bundle.
// *i18n.Bundle satisfies it.
type LanguageValidator interface {
	HasLanguage(code i18n.LanguageCode) bool
}

// Emitter broadcasts changes to the frontend. Wails'
// *application.EventProcessor satisfies it; tests pass nil or a fake.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// Store is the user-scope UI preferences store.
type Store struct {
	path string

	mu      sync.RWMutex
	current UIPreferences

	subsMu sync.Mutex
	subs   []chan UIPreferences

	validator LanguageValidator
	emitter   Emitter
}

// NewStore loads preferences from disk, falling back to defaults. A nil
// validator skips SetLanguage validation; a nil emitter skips broadcasting.
func NewStore(validator LanguageValidator, emitter Emitter) (*Store, error) {
	path, err := preferencesPath()
	if err != nil {
		return nil, fmt.Errorf("resolve preferences path: %w", err)
	}

	// Language starts empty: the frontend treats absence as the signal to
	// detect the browser locale on first launch and call SetLanguage.
	s := &Store{
		path:      path,
		validator: validator,
		emitter:   emitter,
		current:   UIPreferences{ViewMode: DefaultViewMode},
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

// SetViewMode validates, persists, and broadcasts. No-op if unchanged.
func (s *Store) SetViewMode(mode ViewMode) error {
	if !mode.IsValid() {
		return fmt.Errorf("%w: %q", ErrUnsupportedViewMode, mode)
	}

	s.mu.Lock()
	if s.current.ViewMode == mode {
		s.mu.Unlock()
		return nil
	}
	next := s.current
	next.ViewMode = mode
	if err := s.persistLocked(next); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist preferences: %w", err)
	}
	s.current = next
	s.mu.Unlock()

	s.broadcast(next)
	return nil
}

// SetOnboardingCompleted persists the welcome-window dismissal. No-op if unchanged.
func (s *Store) SetOnboardingCompleted(done bool) error {
	s.mu.Lock()
	if s.current.OnboardingCompleted == done {
		s.mu.Unlock()
		return nil
	}
	next := s.current
	next.OnboardingCompleted = done
	if err := s.persistLocked(next); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist preferences: %w", err)
	}
	s.current = next
	s.mu.Unlock()

	s.broadcast(next)
	return nil
}

// SetLanguage validates, persists, and broadcasts. No-op if unchanged.
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

// Subscribe returns a channel of persisted changes and an unsubscribe func.
// The unsubscribe func closes the channel; callers must not close it themselves.
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

// load reads the file into current. A missing file is not an error (the
// in-memory default stands); malformed contents return an error.
func (s *Store) load() error {
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	var loaded UIPreferences
	if _, err := util.ReadJson(s.path, &loaded); err != nil {
		return err
	}

	if !loaded.ViewMode.IsValid() {
		loaded.ViewMode = DefaultViewMode
	}

	s.mu.Lock()
	s.current = loaded
	s.mu.Unlock()
	return nil
}

// persistLocked writes v to disk. Caller must hold s.mu and update in-memory
// state only after this returns nil.
func (s *Store) persistLocked(v UIPreferences) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(s.path), err)
	}
	return util.WriteJson(context.Background(), s.path, v)
}

// broadcast fans v out to subscribers and the emitter. Full-buffer subscribers
// are skipped: consumers only need the latest value, so dropping is safe.
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

func preferencesPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netbird", preferencesFileName), nil
}
