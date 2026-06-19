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

// trayUpdater owns the tray UI that reacts to auto-update. Composed inside Tray.
type trayUpdater struct {
	app          *application.App
	window       *application.WebviewWindow
	update       *services.Update
	notifier     *notifications.NotificationService
	loc          *Localizer
	onIconChange func()
	// onMenuChange drives a full tray relayout: the update row lives in the
	// About submenu, which KDE/Plasma caches on first open and never re-fetches
	// on a plain SetLabel/SetHidden — only a relayout (fresh submenu ids) repaints.
	onMenuChange func()

	mu                 sync.Mutex
	item               *application.MenuItem
	state              updater.State
	notifiedVersion    string
	progressWindowOpen bool
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
	// Seed from cached state to cover an event that fired before wiring completed.
	u.state = update.GetState()
	return u
}

// attach (re)binds the menu item on each Tray.buildMenu run. The caller owns the
// item's OnClick handler.
func (u *trayUpdater) attach(item *application.MenuItem) {
	u.mu.Lock()
	u.item = item
	state := u.state
	u.mu.Unlock()
	u.refreshMenuItem(state)
}

// hasUpdate reports whether the tray should paint the "update available" icon.
func (u *trayUpdater) hasUpdate() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state.Available
}

// applyLanguage re-renders the menu item label after a locale switch.
func (u *trayUpdater) applyLanguage() {
	u.mu.Lock()
	state := u.state
	u.mu.Unlock()
	u.refreshMenuItem(state)
}

// handleClick opens the GitHub releases page when not Enforced, otherwise shows
// the progress page and asks the daemon to start the installer.
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

// applyState diffs st against the cached state and drives the resulting side
// effects: icon repaint, menu refresh, new-version notification, progress window.
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

	// Full relayout rather than in-place: KDE layout-caches the About submenu, so
	// a direct SetLabel/SetHidden wouldn't paint. Fall back if no hook was wired.
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
	_ = safeSendNotification(u.notifier.SendNotification, "update", notifications.NotificationOptions{
		ID:    notifyIDUpdatePrefix + st.Version,
		Title: u.loc.T("notify.update.title"),
		Body:  body,
	})
}

// openProgressWindow points the main window at the /update progress page and
// brings it forward.
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
