//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui/services"
	"github.com/netbirdio/netbird/client/ui/updater"
)

// trayUpdater owns every piece of tray UI that reacts to the auto-update
// feature: the "Download latest / Install version X" menu item, the
// EventUpdateState subscription, the click that either opens the GitHub
// releases page or triggers the in-window installer flow, the OS
// notification for a freshly announced version, and the bring-window-forward
// call when the daemon enters force-install. Composed inside Tray; never
// used standalone.
type trayUpdater struct {
	app      *application.App
	window   *application.WebviewWindow
	update   *services.Update
	notifier *notifications.NotificationService
	loc      *Localizer
	// onIconChange is invoked whenever the "update available" flag
	// transitions, so the tray can repaint its icon (the small badge
	// overlay differs between has-update / no-update).
	onIconChange func()
	// onMenuChange drives a full tray relayout (Tray.relayoutMenu) after an
	// event-driven update-state change. The update row lives in the About
	// submenu, which KDE/Plasma caches on first open and never re-fetches on a
	// plain SetLabel/SetHidden — so a newly-available update would never paint
	// there. relayoutMenu rebuilds the whole tree (fresh submenu ids) and
	// re-attaches this item from the cached state via attach → refreshMenuItem.
	onMenuChange func()

	mu                 sync.Mutex
	item               *application.MenuItem
	state              updater.State
	notifiedVersion    string // last version we surfaced as an OS notification
	progressWindowOpen bool   // last installing value we acted on
}

func newTrayUpdater(app *application.App, window *application.WebviewWindow, update *services.Update, notifier *notifications.NotificationService, loc *Localizer, onIconChange func(), onMenuChange func()) *trayUpdater {
	u := &trayUpdater{
		app:          app,
		window:       window,
		update:       update,
		notifier:     notifier,
		loc:          loc,
		onIconChange: onIconChange,
		onMenuChange: onMenuChange,
	}
	app.Event.On(updater.EventStateChanged, u.onStateEvent)
	// Seed from the cached state so we don't miss an event that fired
	// before NewTray finished wiring (DaemonFeed.Watch starts after tray
	// construction today, but treat that as an implementation detail).
	u.state = update.GetState()
	return u
}

// attach (re)binds the menu item the tray builds for us. Called every time
// Tray.buildMenu runs — initial menu construction and language switches.
// The menu item's OnClick handler is owned by the caller; this method only
// configures label and visibility from the cached state.
func (u *trayUpdater) attach(item *application.MenuItem) {
	u.mu.Lock()
	u.item = item
	state := u.state
	u.mu.Unlock()
	u.refreshMenuItem(state)
}

// hasUpdate reports whether the tray should paint the "update available"
// icon variant. Read by Tray.iconForState during applyIcon.
func (u *trayUpdater) hasUpdate() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state.Available
}

// applyLanguage re-renders the menu item label from the cached state, used
// after Tray.applyLanguage rebuilds the menu with a fresh locale.
func (u *trayUpdater) applyLanguage() {
	u.mu.Lock()
	state := u.state
	u.mu.Unlock()
	u.refreshMenuItem(state)
}

// handleClick runs when the user clicks the tray update entry. Branch 1
// (Enforced=false) opens the GitHub releases page in the browser; Branch 2
// (Enforced=true) surfaces the in-window /update progress page and asks
// the daemon to start the installer.
func (u *trayUpdater) handleClick() {
	u.mu.Lock()
	state := u.state
	u.mu.Unlock()

	if !state.Enforced {
		_ = u.app.Browser.OpenURL(urlGitHubReleases)
		return
	}

	u.openProgressWindow(state.Version)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := u.update.Trigger(ctx); err != nil {
			log.Errorf("trigger update: %v", err)
		}
	}()
}

func (u *trayUpdater) onStateEvent(ev *application.CustomEvent) {
	st, ok := ev.Data.(updater.State)
	if !ok {
		log.Warnf("update state event payload not UpdateState: %T", ev.Data)
		return
	}
	u.applyState(st)
}

// applyState diffs the incoming UpdateState against the cached copy and
// drives every side effect: icon repaint, menu label/visibility, OS
// notification on a newly-announced version, /update window on install
// entry.
func (u *trayUpdater) applyState(st updater.State) {
	u.mu.Lock()
	prev := u.state
	u.state = st

	sendNotify := st.Available && st.Version != "" && st.Version != u.notifiedVersion
	if sendNotify {
		u.notifiedVersion = st.Version
	}

	showWindow := st.Installing && !u.progressWindowOpen
	if showWindow {
		u.progressWindowOpen = true
	} else if !st.Installing {
		u.progressWindowOpen = false
	}
	u.mu.Unlock()

	// Drive a full relayout rather than mutating u.item in place: on KDE the
	// About submenu is layout-cached, so a direct SetLabel/SetHidden here would
	// not paint the newly-available update. relayoutMenu re-attaches the item
	// from u.state, which re-runs refreshMenuItem. Fall back to the in-place
	// refresh if no relayout hook was wired (defensive — always set today).
	if u.onMenuChange != nil {
		u.onMenuChange()
	} else {
		u.refreshMenuItem(st)
	}
	if prev.Available != st.Available && u.onIconChange != nil {
		u.onIconChange()
	}
	if sendNotify {
		u.sendUpdateNotification(st)
	}
	if showWindow {
		u.openProgressWindow(st.Version)
	}
}

// refreshMenuItem updates the menu item's label and visibility from the
// given state. Called from applyState (event-driven), attach (menu rebuild)
// and applyLanguage (locale switch) — all three converge on the same shape.
func (u *trayUpdater) refreshMenuItem(st updater.State) {
	u.mu.Lock()
	item := u.item
	u.mu.Unlock()
	if item == nil {
		return
	}

	if !st.Available {
		item.SetHidden(true)
		return
	}
	if st.Enforced {
		item.SetLabel(u.loc.T("tray.menu.installVersion", "version", st.Version))
	} else {
		item.SetLabel(u.loc.T("tray.menu.downloadLatest"))
	}
	item.SetHidden(false)
}

func (u *trayUpdater) sendUpdateNotification(st updater.State) {
	if u.notifier == nil {
		return
	}
	body := u.loc.T("notify.update.body", "version", st.Version)
	if st.Enforced {
		body += u.loc.T("notify.update.enforcedSuffix")
	}
	if err := u.notifier.SendNotification(notifications.NotificationOptions{
		ID:    notifyIDUpdatePrefix + st.Version,
		Title: u.loc.T("notify.update.title"),
		Body:  body,
	}); err != nil {
		log.Debugf("send update notification: %v", err)
	}
}

// openProgressWindow points the main window at the /update progress page
// and brings it forward. Used both when the user clicks an enforced-update
// menu entry (Branch 2) and when the daemon flips Installing to true on
// its own (Branch 3, force install).
func (u *trayUpdater) openProgressWindow(version string) {
	if u.window == nil {
		return
	}
	url := "/#/update"
	if version != "" {
		url += "?version=" + version
	}
	u.window.SetURL(url)
	u.window.Show()
	u.window.Focus()
}
