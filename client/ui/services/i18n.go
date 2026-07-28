//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/i18n"
)

// I18n is the Wails-bound facade over i18n.Bundle; the translation logic lives
// in client/ui/i18n.
type I18n struct {
	bundle *i18n.Bundle
}

func NewI18n(bundle *i18n.Bundle) *I18n {
	return &I18n{bundle: bundle}
}

// Languages returns the shipped locales.
func (s *I18n) Languages(_ context.Context) ([]i18n.Language, error) {
	return s.bundle.Languages(), nil
}

// Bundle returns the full key->text map so the React side can drive its own
// translation library off the same source bundles.
func (s *I18n) Bundle(_ context.Context, code i18n.LanguageCode) (map[string]string, error) {
	return s.bundle.BundleFor(code)
}
