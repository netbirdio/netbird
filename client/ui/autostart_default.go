//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/ui/preferences"
	"github.com/netbirdio/netbird/client/ui/services"
)

// freshInstallBreadcrumbName is the marker file written by the platform
// installers on a fresh install only, never on an upgrade. Its presence is
// the update-safety gate for the autostart default: upgrading users never
// have it, so an update can never trigger a login-item write.
const freshInstallBreadcrumbName = ".fresh-install"

// autostartDefaultState carries the guard inputs of the one-time autostart
// default decision so the decision itself stays a pure, testable function.
type autostartDefaultState struct {
	supported          bool
	mdmDisabled        bool
	postUpdateRelaunch bool
	breadcrumbPresent  bool
}

// shouldEnableAutostartDefault applies the first-run guards in order and
// returns whether autostart may be enabled, plus the reason when it may not.
func shouldEnableAutostartDefault(s autostartDefaultState) (bool, string) {
	switch {
	case !s.supported:
		return false, "autostart not supported on this platform"
	case s.mdmDisabled:
		return false, "autostart disabled by MDM policy"
	case s.postUpdateRelaunch:
		return false, "post-update relaunch"
	case !s.breadcrumbPresent:
		return false, "no fresh-install breadcrumb"
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

// freshInstallBreadcrumbPath returns the installer-written breadcrumb
// location for the current platform, or "" when there is none.
func freshInstallBreadcrumbPath() string {
	switch runtime.GOOS {
	case "windows":
		exe, err := os.Executable()
		if err != nil {
			log.Debugf("resolve executable path for fresh-install breadcrumb: %v", err)
			return ""
		}
		return filepath.Join(filepath.Dir(exe), freshInstallBreadcrumbName)
	case "darwin":
		return filepath.Join("/Library/Application Support/NetBird", freshInstallBreadcrumbName)
	case "linux":
		return filepath.Join("/var/lib/netbird", freshInstallBreadcrumbName)
	}
	return ""
}

// applyAutostartDefault runs the one-time launch-on-login default for fresh
// installs. The autostartInitialized marker is persisted before any enable
// attempt so a crash mid-flow degrades to "never enabled" instead of
// retrying login-item writes on every launch. A user's later disable in
// Settings is never overridden: the marker guarantees at-most-once, ever.
func applyAutostartDefault(ctx context.Context, autostart *services.Autostart, prefs *preferences.Store, postUpdateRelaunch bool) {
	if prefs.Get().AutostartInitialized {
		return
	}
	if err := prefs.SetAutostartInitialized(true); err != nil {
		log.Warnf("failed to persist autostart marker, skipping autostart default: %v", err)
		return
	}

	breadcrumb := freshInstallBreadcrumbPath()
	state := autostartDefaultState{
		supported:          autostart.Supported(ctx),
		mdmDisabled:        autostartDisabledByMDM(mdm.LoadPolicy()),
		postUpdateRelaunch: postUpdateRelaunch,
		breadcrumbPresent:  breadcrumb != "" && fileExists(breadcrumb),
	}
	enable, reason := shouldEnableAutostartDefault(state)
	if !enable {
		log.Debugf("skipping autostart default: %s", reason)
		return
	}

	if err := autostart.SetEnabled(ctx, true); err != nil {
		log.Warnf("failed to enable autostart on fresh install: %v", err)
		return
	}
	log.Info("autostart enabled by default on fresh install")

	if err := os.Remove(breadcrumb); err != nil {
		log.Debugf("failed to remove fresh-install breadcrumb %s: %v", breadcrumb, err)
	}
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
