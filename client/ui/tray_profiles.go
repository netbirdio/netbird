//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/ui/services"
)

// loadConfig caches the active-profile identity and the notifications gate.
// Runs in a startup goroutine so a slow daemon does not block menu construction.
func (t *Tray) loadConfig() {
	ctx := context.Background()

	active, err := t.svc.Profiles.GetActive(ctx)
	if err != nil {
		log.Debugf("get active profile: %v", err)
		return
	}
	cfg, err := t.svc.Settings.GetConfig(ctx, services.ConfigParams(active))
	if err != nil {
		log.Debugf("get config: %v", err)
		return
	}

	t.profileMu.Lock()
	t.activeProfile = active.ProfileName
	t.activeUsername = active.Username
	t.notificationsEnabled = !cfg.DisableNotifications
	t.profileMu.Unlock()
}

// loadProfiles fetches the profile list and relayouts the menu. Also called
// from applyStatus to catch flips from another channel (CLI, autoconnect),
// since the daemon emits no active-profile event. Full relayout (not
// Clear()+Add()) is required for KDE/Plasma — see relayoutMenu's doc comment.
func (t *Tray) loadProfiles() {
	t.profileLoadMu.Lock()
	defer t.profileLoadMu.Unlock()
	ctx := context.Background()

	username, err := t.svc.Profiles.Username()
	if err != nil {
		log.Debugf("get current user: %v", err)
		return
	}
	profiles, err := t.svc.Profiles.List(ctx, username)
	if err != nil {
		log.Debugf("list profiles: %v", err)
		return
	}

	t.profilesMu.Lock()
	t.profiles = profiles
	t.profilesUser = username
	t.profilesMu.Unlock()

	t.relayoutMenu()
}

// fillProfileSubmenu paints cached profile rows into the freshly built submenu.
// Pure UI: never fetches, never calls SetMenu (relayoutMenu owns the SetMenu).
func (t *Tray) fillProfileSubmenu() {
	if t.profileSubmenu == nil {
		return
	}
	t.profilesMu.Lock()
	profiles := append([]services.Profile(nil), t.profiles...)
	username := t.profilesUser
	t.profilesMu.Unlock()

	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	// Wails' systray does not reliably propagate a disabled parent to its
	// children on every platform, so disable each row explicitly.
	disableProfiles, _ := t.featuresDisabled()

	t.profileSubmenu.Clear()
	var activeName, activeEmail string
	for _, p := range profiles {
		name := p.Name
		active := p.IsActive
		// Add, not AddCheckbox: Wails auto-toggles a checkbox on click before
		// OnClick fires, so both old and new would briefly show checked during
		// the switch. A plain item with a "✓ " prefix avoids the race.
		label := name
		if active {
			label = "✓ " + name
		}
		item := t.profileSubmenu.Add(label)
		item.OnClick(func(*application.Context) {
			log.Infof("tray profile click: profile=%q wasActive=%v", name, active)
			if active {
				return
			}
			t.switchProfile(name)
		})
		item.SetEnabled(!disableProfiles)
		if active {
			activeName = name
			activeEmail = p.Email
		}
	}
	t.profileSubmenu.AddSeparator()
	manageProfiles := t.profileSubmenu.Add(t.loc.T("tray.menu.manageProfiles"))
	manageProfiles.OnClick(func(*application.Context) {
		t.svc.WindowManager.OpenSettings("profiles")
	})
	manageProfiles.SetEnabled(!disableProfiles)
	log.Infof("tray fillProfileSubmenu: %d profile(s) for user %q, active=%q", len(profiles), username, activeName)
	if t.profileSubmenuItem != nil && activeName != "" {
		t.profileSubmenuItem.SetLabel(activeName)
	}
	if t.profileEmailItem != nil {
		if activeEmail != "" {
			t.profileEmailItem.SetLabel(fmt.Sprintf("(%s)", activeEmail))
			t.profileEmailItem.SetHidden(false)
		} else {
			t.profileEmailItem.SetHidden(true)
		}
	}
}

// switchProfile cancels any in-flight switch before starting a new one, so
// rapid clicks converge to the last selected profile. Optimistic paint and
// event suppression live in ProfileSwitcher, shared with the React Status page.
func (t *Tray) switchProfile(name string) {
	t.profileMu.Lock()
	if t.switchCancel != nil {
		t.switchCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.switchCancel = cancel
	t.profileMu.Unlock()

	go func() {
		username, err := t.svc.Profiles.Username()
		if err != nil {
			log.Errorf("tray switchProfile: get current user: %v", err)
			return
		}
		if err := t.svc.ProfileSwitcher.SwitchActive(ctx, services.ProfileRef{
			ProfileName: name,
			Username:    username,
		}); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("tray switchProfile: %v", err)
			t.notifyError(t.loc.T("notify.error.switchProfile", "profile", name))
			return
		}
		t.loadProfiles()
	}()
}
