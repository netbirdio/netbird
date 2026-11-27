//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// mdmDefaultsFrom reads the cosmetic preferences an MDM policy proposes.
func mdmDefaultsFrom(policy *mdm.Policy) preferences.MDMDefaults {
	var d preferences.MDMDefaults
	if v, ok := policy.GetString(mdm.KeyDefaultLanguage); ok {
		lang := i18n.LanguageCode(strings.TrimSpace(v))
		d.Language = &lang
	}
	if v, ok := policy.GetString(mdm.KeyDefaultViewMode); ok {
		mode := preferences.ViewMode(strings.TrimSpace(v))
		d.ViewMode = &mode
	}
	if v, ok := policy.GetString(mdm.KeyDefaultTheme); ok {
		theme := preferences.Theme(strings.TrimSpace(v))
		d.Theme = &theme
	}
	return d
}

// applyMDMDefaults applies the policy's default preferences once at startup.
func applyMDMDefaults(prefs *preferences.Store, policy *mdm.Policy) {
	if err := prefs.ApplyMDMDefaults(mdmDefaultsFrom(policy)); err != nil {
		log.Warnf("apply MDM default preferences: %v", err)
	}
}

// watchMDMDefaults re-applies the default preferences when the policy changes.
// The app polls the policy itself because the daemon only signals a policy
// change while the connection is up.
func watchMDMDefaults(ctx context.Context, prefs *preferences.Store, ticker *mdm.Ticker) {
	ticker.Run(ctx, func(_, curr *mdm.Policy) error {
		return prefs.ApplyMDMDefaults(mdmDefaultsFrom(curr))
	})
}
