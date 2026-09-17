//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ui/services"
)

// formatProfileLabel returns the display label for a profile. Profiles can
// share the same Name, so when more than one profile in profiles carries this
// Name, a short form of the ID is appended to disambiguate the entries.
func formatProfileLabel(profile services.Profile, profiles []services.Profile) string {
	count := 0
	for _, p := range profiles {
		if p.Name == profile.Name {
			count++
		}
	}
	if count <= 1 {
		return profile.Name
	}
	return fmt.Sprintf("%s (%s)", profile.Name, profilemanager.ID(profile.ID).ShortID())
}

// loadConfig caches the active-profile identity and the notifications gate.
// Runs in a startup goroutine so a slow daemon does not block menu construction.
func (t *Tray) loadConfig() {
	ctx := context.Background()

	active, err := t.svc.Profiles.GetActive(ctx)
	if err != nil {
		log.Debugf("get active profile: %v", err)
		return
	}
	// Address the active profile by ID (the daemon resolves it as a handle),
	// since display names can collide. ConfigParams no longer matches
	// ActiveProfile's shape for a struct conversion now that it carries an ID.
	cfg, err := t.svc.Settings.GetConfig(ctx, services.ConfigParams{
		ProfileName: active.ID,
		Username:    active.Username,
	})
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

	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].Name != profiles[j].Name {
			return profiles[i].Name < profiles[j].Name
		}
		return profiles[i].ID < profiles[j].ID
	})

	// Wails' systray does not reliably propagate a disabled parent to its
	// children on every platform, so disable each row explicitly.
	disableProfiles, _ := t.featuresDisabled()

	t.profileSubmenu.Clear()
	var activeName, activeEmail string
	for _, p := range profiles {
		id := p.ID
		// Display names can collide, so disambiguate with a short ID suffix.
		display := formatProfileLabel(p, profiles)
		active := p.IsActive
		// Add, not AddCheckbox: Wails auto-toggles a checkbox on click before
		// OnClick fires, so both old and new would briefly show checked during
		// the switch. A plain item with a "✓ " prefix avoids the race.
		label := display
		if active {
			label = "✓ " + display
		}
		item := t.profileSubmenu.Add(label)
		item.OnClick(func(*application.Context) {
			log.Infof("tray profile click: profile=%q id=%q wasActive=%v", display, id, active)
			if active {
				return
			}
			t.switchProfile(id, display)
		})
		item.SetEnabled(!disableProfiles)
		if active {
			activeName = display
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
// switchProfile sends handle (the profile's ID) to the daemon, which resolves
// it precisely even when display names collide. display is used only for the
// failure notification.
func (t *Tray) switchProfile(handle, display string) {
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
			ProfileName: handle,
			Username:    username,
		}); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("tray switchProfile: %v", err)
			t.notifyError(t.loc.T("notify.error.switchProfile", "profile", display))
			return
		}
		t.loadProfiles()
	}()
}
