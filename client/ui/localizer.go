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

// Localizer caches the active language so key lookups skip the preferences store.
//
// Kept in the main package (not i18n/) because StatusLabel maps daemon
// status enum strings to translations; moving it would invert the
// dependency direction.
type Localizer struct {
	bundle *i18n.Bundle
	store  *preferences.Store

	mu   sync.RWMutex
	lang i18n.LanguageCode

	unsubscribe func()
}

// NewLocalizer seeds the active language from the on-disk preference. Either
// argument may be nil (tests): T then returns the raw key and Watch is a no-op.
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

// Language returns the active language code.
func (l *Localizer) Language() i18n.LanguageCode {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lang
}

// T resolves key in the current language; args are {placeholder}/value pairs.
// With no bundle wired it returns key unchanged.
func (l *Localizer) T(key string, args ...string) string {
	if l == nil || l.bundle == nil {
		return key
	}
	l.mu.RLock()
	lang := l.lang
	l.mu.RUnlock()
	return l.bundle.Translate(lang, key, args...)
}

// Watch invokes cb on each language change, after the cached language is
// updated so cb may call l.T with the new locale. Replaces any prior subscription.
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

// Close cancels the preference subscription.
func (l *Localizer) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.unsubscribe != nil {
		l.unsubscribe()
		l.unsubscribe = nil
	}
}

// StatusLabel maps a daemon status string to its tray label; unrecognised
// statuses pass through verbatim.
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
