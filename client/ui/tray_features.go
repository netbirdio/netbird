//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// refreshRestrictions re-reads the operator-disabled UI flags and re-gates the
// menu. Must run on every config_changed event: the daemon re-applies its MDM
// policy on each engine spawn.
func (t *Tray) refreshRestrictions() {
	r, err := t.svc.Settings.GetRestrictions(context.Background())
	if err != nil {
		log.Debugf("get restrictions: %v", err)
		return
	}
	t.featureMu.Lock()
	changed := t.disableProfiles != r.Features.DisableProfiles ||
		t.disableNetworks != r.Features.DisableNetworks
	t.disableProfiles = r.Features.DisableProfiles
	t.disableNetworks = r.Features.DisableNetworks
	t.featureMu.Unlock()
	// relayoutMenu rebuilds the whole tree, so skip the no-op refresh (common case).
	if changed {
		t.relayoutMenu()
	}
}

// featuresDisabled returns the cached flags under featureMu.
func (t *Tray) featuresDisabled() (profiles, networks bool) {
	t.featureMu.Lock()
	defer t.featureMu.Unlock()
	return t.disableProfiles, t.disableNetworks
}
