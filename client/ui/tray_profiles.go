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

// loadConfig seeds the in-process notifications gate from the daemon's
// stored config and caches the active-profile identity for any future
// SetConfig calls. Called once at startup from a goroutine so a slow or
// unreachable daemon does not block menu construction.
//
// The Settings page in the main window is the source of truth for every
// other knob (SSH, auto-connect, Rosenpass, lazy connections, block-inbound,
// notifications); we only mirror the notifications flag because the tray
// itself uses it to gate OS toasts in onSystemEvent.
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

// loadProfiles refreshes the Profiles submenu from the daemon. Each
// entry is a checkbox showing the active profile and switches on click.
// Called on ApplicationStarted, after a successful switchProfile, and
// from applyStatus whenever the daemon's status text changes — the
// last case catches profile flips driven by another channel (CLI
// "netbird profile select", autoconnect picking the persisted profile
// after the UI's first ListProfiles, etc.) since the daemon does not
// emit a dedicated active-profile event.
func (t *Tray) loadProfiles() {
	if t.profileSubmenu == nil {
		return
	}
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
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	t.profileSubmenu.Clear()
	var activeName, activeEmail string
	for _, p := range profiles {
		name := p.Name
		active := p.IsActive
		// Use Add instead of AddCheckbox: Wails auto-toggles a checkbox's
		// checked state on click (before the OnClick handler fires), so with
		// AddCheckbox both the old and the new profile would briefly show as
		// checked while the switchProfile goroutine is running. A plain item
		// with a "✓ " prefix avoids the race entirely.
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
		if active {
			activeName = name
			activeEmail = p.Email
		}
	}
	t.profileSubmenu.AddSeparator()
	t.profileSubmenu.Add(t.loc.T("tray.menu.manageProfiles")).OnClick(func(*application.Context) {
		t.svc.WindowManager.OpenSettings("profiles")
	})
	log.Infof("tray loadProfiles: received %d profile(s) for user %q, active=%q", len(profiles), username, activeName)
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
	// Wails v3 alpha's submenu.Update() builds a fresh, detached NSMenu on
	// darwin that never replaces the empty NSMenu attached to the parent
	// menu item at initial setup — so the visible Profiles menu stays
	// frozen on the snapshot taken when the tray was registered. Re-running
	// SetMenu on the top-level rebuilds the entire NSMenu tree against the
	// cached pointer and is the only path that propagates submenu changes.
	if t.menu != nil {
		t.tray.SetMenu(t.menu)
	} else {
		t.profileSubmenu.Update()
	}
}

// switchProfile cancels any in-flight profile switch, then starts a new one.
// Cancelling the previous context aborts its in-flight gRPC calls (Down/Up)
// so rapid clicks always converge to the last selected profile.
//
// The optimistic Connecting paint (and suppression of the transient
// Idle/stale Connected daemon events that follow Down) lives in
// services/daemon_feed.go — ProfileSwitcher calls DaemonFeed.BeginProfileSwitch
// when the previous status was Connected/Connecting, which emits a
// synthetic Connecting status to the event bus and starts filtering
// the daemon stream. That way both this tray and the React Status
// page see the same optimistic state without duplicating policy.
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
