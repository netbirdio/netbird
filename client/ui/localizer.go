//go:build !android && !ios && !freebsd && !js

package main

import (
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
	"github.com/netbirdio/netbird/client/ui/services"
)

// Localizer is the tray's bridge to the i18n bundle and preferences store.
// It caches the active language so every menu-build pass and notification
// call can resolve a key without re-querying preferences, and it owns
// the preference-subscription lifecycle so consumers don't have to.
//
// Kept in the main package (not i18n/) because StatusLabel maps daemon
// status enum strings (services.StatusIdle, services.StatusDaemonUnavailable)
// to translations — pulling those into i18n would invert the dependency
// direction.
type Localizer struct {
	bundle *i18n.Bundle
	store  *preferences.Store

	mu   sync.RWMutex
	lang i18n.LanguageCode

	unsubscribe func()
}

// NewLocalizer seeds the active language from the on-disk preference so
// the first menu render is already in the right locale. Either argument
// may be nil — useful for tests/dry-runs — in which case Translate falls
// back to the raw key and Watch is a no-op.
func NewLocalizer(bundle *i18n.Bundle, store *preferences.Store) *Localizer {
	l := &Localizer{
		bundle: bundle,
		store:  store,
		lang:   i18n.DefaultLanguage,
	}
	if store != nil {
		if p := store.Get(); p.Language != "" {
			l.lang = p.Language
		}
	}
	return l
}

// Language returns the BCP-47 code currently driving translations.
func (l *Localizer) Language() i18n.LanguageCode {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lang
}

// T resolves key in the current language with optional {placeholder}/value
// argument pairs. When no bundle is wired the key is returned as-is so
// callers always get a non-empty string.
func (l *Localizer) T(key string, args ...string) string {
	if l == nil || l.bundle == nil {
		return key
	}
	l.mu.RLock()
	lang := l.lang
	l.mu.RUnlock()
	return l.bundle.Translate(lang, key, args...)
}

// Watch subscribes to preference changes; cb fires for each new language
// (after the Localizer's own cached language has been updated, so cb can
// call l.T to render with the new locale). Safe to call once per
// Localizer; later calls overwrite the previous subscription.
func (l *Localizer) Watch(cb func(lang i18n.LanguageCode)) {
	if l.store == nil {
		return
	}
	ch, unsubscribe := l.store.Subscribe()
	l.mu.Lock()
	if l.unsubscribe != nil {
		l.unsubscribe()
	}
	l.unsubscribe = unsubscribe
	l.mu.Unlock()

	go func() {
		for p := range ch {
			if p.Language == "" {
				continue
			}
			l.mu.Lock()
			if l.lang == p.Language {
				l.mu.Unlock()
				continue
			}
			l.lang = p.Language
			l.mu.Unlock()
			log.Infof("localizer: language switched to %s", p.Language)
			if cb != nil {
				cb(p.Language)
			}
		}
	}()
}

// Close drops the preference subscription. Currently unused (the tray
// lives for the whole process) but kept so a future shutdown path can
// release the channel cleanly.
func (l *Localizer) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.unsubscribe != nil {
		l.unsubscribe()
		l.unsubscribe = nil
	}
}

// StatusLabel maps a daemon status string to its user-facing tray label.
// Idle and the daemon-unavailable sentinel get translated phrasing; every
// other status passes through verbatim (matches the legacy behaviour of
// surfacing the raw daemon enum for the connecting/needs-login states).
func (l *Localizer) StatusLabel(status string) string {
	switch {
	case status == "", strings.EqualFold(status, services.StatusIdle):
		return l.T("tray.status.disconnected")
	case strings.EqualFold(status, services.StatusDaemonUnavailable):
		return l.T("tray.status.daemonUnavailable")
	case strings.EqualFold(status, services.StatusConnected):
		return l.T("tray.status.connected")
	case strings.EqualFold(status, services.StatusConnecting):
		return l.T("tray.status.connecting")
	case strings.EqualFold(status, services.StatusNeedsLogin):
		return l.T("tray.status.needsLogin")
	case strings.EqualFold(status, services.StatusLoginFailed):
		return l.T("tray.status.loginFailed")
	case strings.EqualFold(status, services.StatusSessionExpired):
		return l.T("tray.status.sessionExpired")
	}
	return status
}
