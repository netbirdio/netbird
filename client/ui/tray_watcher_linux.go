//go:build linux && !(linux && 386)

package main

// startStatusNotifierWatcher registers org.kde.StatusNotifierWatcher on the
// session D-Bus if no other process has already claimed it.
//
// Minimal window managers (Fluxbox, OpenBox, i3, etc.) do not ship a
// StatusNotifier watcher, so tray icons using libayatana-appindicator or
// the KDE/freedesktop StatusNotifier protocol silently fail.
//
// By owning the watcher name in-process we allow the Wails v3 built-in tray
// to register itself — no external daemon or package needed.
//
// When an XEmbed system tray is available (_NET_SYSTEM_TRAY_S0), we also
// start an in-process XEmbed host that bridges the SNI icon into the
// XEmbed tray (Fluxbox, IceWM, etc.).

import (
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = "/StatusNotifierWatcher"
	watcherIface = "org.kde.StatusNotifierWatcher"
)

type statusNotifierWatcher struct {
	conn    *dbus.Conn
	items   []string
	hosts   map[string]*xembedHost
	hostsMu sync.Mutex
}

// RegisterStatusNotifierItem is the D-Bus method called by tray clients.
// The sender parameter is automatically injected by godbus with the caller's
// unique bus name (e.g. ":1.42"). It does not appear in the D-Bus signature.
func (w *statusNotifierWatcher) RegisterStatusNotifierItem(sender dbus.Sender, service string) *dbus.Error {
	for _, s := range w.items {
		if s == service {
			return nil
		}
	}
	w.items = append(w.items, service)
	log.Debugf("StatusNotifierWatcher: registered item %q from %s", service, sender)

	go w.tryStartXembedHost(string(sender), dbus.ObjectPath(service))
	return nil
}

// RegisterStatusNotifierHost is required by the protocol but unused here.
func (w *statusNotifierWatcher) RegisterStatusNotifierHost(service string) *dbus.Error {
	log.Debugf("StatusNotifierWatcher: host registered %q", service)
	return nil
}

// tryStartXembedHost attempts to create an XEmbed tray icon for the given
// SNI item. If no XEmbed tray manager is available, this is a no-op.
func (w *statusNotifierWatcher) tryStartXembedHost(busName string, objPath dbus.ObjectPath) {
	w.hostsMu.Lock()
	defer w.hostsMu.Unlock()

	if _, exists := w.hosts[busName]; exists {
		return
	}

	// Use a private session bus so our signal subscriptions don't
	// interfere with Wails' signal handler (which panics on unexpected signals).
	sessionConn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: cannot open private session bus for XEmbed host: %v", err)
		return
	}
	if err := sessionConn.Auth(nil); err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host auth failed: %v", err)
		_ = sessionConn.Close()
		return
	}
	if err := sessionConn.Hello(); err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host Hello failed: %v", err)
		_ = sessionConn.Close()
		return
	}

	host, err := newXembedHost(sessionConn, busName, objPath)
	if err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host not started: %v", err)
		return
	}

	w.hosts[busName] = host
	go host.run()
	log.Infof("StatusNotifierWatcher: XEmbed tray icon created for %s", busName)
}

// startStatusNotifierWatcher claims org.kde.StatusNotifierWatcher on the
// session bus if it is not already provided by another process.
// Safe to call unconditionally — it does nothing when a real watcher is present.
func startStatusNotifierWatcher() {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: cannot open private session bus: %v", err)
		return
	}
	if err := conn.Auth(nil); err != nil {
		log.Debugf("StatusNotifierWatcher: auth failed: %v", err)
		_ = conn.Close()
		return
	}
	if err := conn.Hello(); err != nil {
		log.Debugf("StatusNotifierWatcher: Hello failed: %v", err)
		_ = conn.Close()
		return
	}

	// Check whether another process already owns the watcher name.
	var owner string
	callErr := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, watcherName).Store(&owner)
	if callErr == nil && owner != "" {
		log.Debugf("StatusNotifierWatcher: already owned by %s, skipping", owner)
		_ = conn.Close()
		return
	}

	reply, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Debugf("StatusNotifierWatcher: could not claim name (reply=%v err=%v)", reply, err)
		_ = conn.Close()
		return
	}

	w := &statusNotifierWatcher{
		conn:  conn,
		hosts: make(map[string]*xembedHost),
	}
	if err := conn.ExportAll(w, dbus.ObjectPath(watcherPath), watcherIface); err != nil {
		log.Errorf("StatusNotifierWatcher: export failed: %v", err)
		_ = conn.Close()
		return
	}

	log.Infof("StatusNotifierWatcher: active on session bus (enables tray on minimal WMs)")
	// Connection intentionally kept open for the lifetime of the process.
}
