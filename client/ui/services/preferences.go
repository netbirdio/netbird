//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// Preferences is the Wails-bound facade over preferences.Store. The store
// itself owns persistence and the subscription channel; this type just
// re-exposes Get and SetLanguage with the context.Context-first signature
// the Wails binding generator wants.
type Preferences struct {
	store *preferences.Store
}

func NewPreferences(store *preferences.Store) *Preferences {
	return &Preferences{store: store}
}

// Get returns the current user-scope preferences.
func (s *Preferences) Get(_ context.Context) (preferences.UIPreferences, error) {
	return s.store.Get(), nil
}

// SetLanguage validates and persists a new UI language.
func (s *Preferences) SetLanguage(_ context.Context, lang i18n.LanguageCode) error {
	return s.store.SetLanguage(lang)
}
