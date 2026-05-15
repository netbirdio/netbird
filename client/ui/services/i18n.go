//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/i18n"
)

// I18n is the Wails-bound facade over i18n.Bundle. It exists only to give
// the binding generator a service type with the context.Context-first
// signatures it expects; the translation logic, locale loading and the
// LanguageCode type all live in client/ui/i18n.
type I18n struct {
	bundle *i18n.Bundle
}

func NewI18n(bundle *i18n.Bundle) *I18n {
	return &I18n{bundle: bundle}
}

// Languages exposes the list of shipped locales to the frontend so the
// settings page can populate its language picker.
func (s *I18n) Languages(_ context.Context) ([]i18n.Language, error) {
	return s.bundle.Languages(), nil
}

// Bundle returns the full key->text map for one language, letting the
// React side drive its own translation library (i18next, etc.) off the
// same source bundles the tray uses.
func (s *I18n) Bundle(_ context.Context, code i18n.LanguageCode) (map[string]string, error) {
	return s.bundle.BundleFor(code)
}
