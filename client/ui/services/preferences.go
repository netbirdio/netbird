//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// Preferences is the Wails-bound facade over preferences.Store; the context.Context-first
// signatures are what the binding generator requires.
type Preferences struct {
	store *preferences.Store
}

func NewPreferences(store *preferences.Store) *Preferences {
	return &Preferences{store: store}
}

func (s *Preferences) Get(_ context.Context) (preferences.UIPreferences, error) {
	return s.store.Get(), nil
}

func (s *Preferences) SetLanguage(_ context.Context, lang i18n.LanguageCode) error {
	return s.store.SetLanguage(lang)
}

func (s *Preferences) SetViewMode(_ context.Context, mode preferences.ViewMode) error {
	return s.store.SetViewMode(mode)
}

func (s *Preferences) SetOnboardingCompleted(_ context.Context, done bool) error {
	return s.store.SetOnboardingCompleted(done)
}
