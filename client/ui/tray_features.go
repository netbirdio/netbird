//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// refreshFeatures pulls the daemon's operator-disabled UI surfaces
// (DisableProfiles / DisableNetworks) and re-applies the tray menu gating.
// Called once at startup (ApplicationStarted) and on every config_changed
// system event — the daemon re-applies its MDM policy on each engine spawn
// and emits that event, so this is the tray's signal to re-sync the kill
// switches. It replaces the legacy Fyne UI's 2s GetFeatures poll.
func (t *Tray) refreshFeatures() {
	features, err := t.svc.Settings.GetFeatures(context.Background())
	if err != nil {
		log.Debugf("get features: %v", err)
		return
	}
	t.featureMu.Lock()
	changed := t.disableProfiles != features.DisableProfiles ||
		t.disableNetworks != features.DisableNetworks
	t.disableProfiles = features.DisableProfiles
	t.disableNetworks = features.DisableNetworks
	t.featureMu.Unlock()
	// Repaint only when a flag actually flipped: relayoutMenu rebuilds the
	// whole menu tree, so a no-op refresh (the common case) must not churn
	// it. relayoutMenu and fillProfileSubmenu read the cached flags via
	// featuresDisabled, so the new state applies regardless of which relayout
	// (this one, a status push, or a profile reload) runs last.
	if changed {
		t.relayoutMenu()
	}
}

// featuresDisabled returns the cached DisableProfiles / DisableNetworks kill
// switches under featureMu. Read by relayoutMenu, refreshMenuItemsForStatus,
// and fillProfileSubmenu to grey out the Profiles and Exit Node menus when
// the operator (or an MDM policy) disabled those surfaces server-side.
func (t *Tray) featuresDisabled() (profiles, networks bool) {
	t.featureMu.Lock()
	defer t.featureMu.Unlock()
	return t.disableProfiles, t.disableNetworks
}
