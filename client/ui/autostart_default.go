//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/ui/preferences"
	"github.com/netbirdio/netbird/client/ui/services"
)

// autostartDefaultState carries the guard inputs of the one-time autostart
// default decision so the decision itself stays a pure, testable function.
type autostartDefaultState struct {
	supported    bool
	mdmDisabled  bool
	priorInstall bool
}

// shouldEnableAutostartDefault applies the first-run guards in order and
// returns whether autostart may be enabled, plus the reason when it may not.
func shouldEnableAutostartDefault(s autostartDefaultState) (bool, string) {
	switch {
	case !s.supported:
		return false, "autostart not supported on this platform"
	case s.mdmDisabled:
		return false, "autostart disabled by MDM policy"
	case s.priorInstall:
		return false, "existing NetBird installation"
	}
	return true, ""
}

// autostartDisabledByMDM reports whether the MDM policy manages the
// disableAutostart key in a way that must suppress the default. An
// unparseable managed value is treated as disabled to stay on the safe side.
func autostartDisabledByMDM(policy *mdm.Policy) bool {
	if !policy.HasKey(mdm.KeyDisableAutostart) {
		return false
	}
	disabled, ok := policy.GetBool(mdm.KeyDisableAutostart)
	return !ok || disabled
}

// netbirdFootprintExists reports whether the machine already carries NetBird
// daemon config or state, meaning this is not a genuinely fresh install. It is
// the update-safety gate for the autostart default: upgrading users always
// have a footprint, so an update can never trigger a login-item write.
func netbirdFootprintExists() bool {
	candidates := []string{
		profilemanager.DefaultConfigPath,
		filepath.Join(profilemanager.DefaultConfigPathDir, "config.json"),
		filepath.Join(profilemanager.DefaultConfigPathDir, "state.json"),
	}
	for _, path := range candidates {
		if path != "" && fileExists(path) {
			return true
		}
	}
	return false
}

// applyAutostartDefault runs the one-time launch-on-login default for genuinely
// fresh installs. The autostartInitialized marker is persisted before any
// enable attempt so a crash mid-flow degrades to "never enabled" instead of
// retrying login-item writes on every launch. A user's later disable in
// Settings is never overridden: the marker guarantees at-most-once, ever.
func applyAutostartDefault(ctx context.Context, autostart *services.Autostart, prefs *preferences.Store, prefsFileExisted bool) {
	priorFootprint := netbirdFootprintExists() || prefsFileExisted

	if prefs.Get().AutostartInitialized {
		return
	}
	if err := prefs.SetAutostartInitialized(true); err != nil {
		log.Warnf("persist autostart marker, skipping autostart default: %v", err)
		return
	}

	state := autostartDefaultState{
		supported:    autostart.Supported(ctx),
		mdmDisabled:  autostartDisabledByMDM(mdm.LoadPolicy()),
		priorInstall: priorFootprint,
	}
	enable, reason := shouldEnableAutostartDefault(state)
	if !enable {
		log.Debugf("skipping autostart default: %s", reason)
		return
	}

	if err := autostart.SetEnabled(ctx, true); err != nil {
		log.Warnf("enable autostart on fresh install: %v", err)
		return
	}
	log.Info("autostart enabled by default on fresh install")
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
