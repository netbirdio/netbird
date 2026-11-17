//go:build linux && !(linux && 386)

package main

// In-process org.kde.StatusNotifierWatcher for minimal WMs (Fluxbox, OpenBox,
// i3) that ship no watcher. When an XEmbed tray exists (_NET_SYSTEM_TRAY_S0),
// an in-process XEmbed host bridges the SNI icon into it.

import (
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = "/StatusNotifierWatcher"
	watcherIface = "org.kde.StatusNotifierWatcher"

	// The UI is often autostarted before the panel on minimal WMs, so a single
	// startup probe would miss a tray that appears a second later.
	watcherProbeInterval = 500 * time.Millisecond
	watcherProbeTimeout  = 10 * time.Second
)

type statusNotifierWatcher struct {
	conn    *dbus.Conn
	items   []string
	hosts   map[string]*xembedHost
	hostsMu sync.Mutex
}

// RegisterStatusNotifierItem is the D-Bus method called by tray clients.
// sender is injected by godbus and is not part of the D-Bus signature.
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

// tryStartXembedHost is a no-op when no XEmbed tray manager is available.
func (w *statusNotifierWatcher) tryStartXembedHost(busName string, objPath dbus.ObjectPath) {
	w.hostsMu.Lock()
	defer w.hostsMu.Unlock()

	if _, exists := w.hosts[busName]; exists {
		return
	}

	// Private session bus so our signal subscriptions don't reach Wails'
	// signal handler, which panics on unexpected signals.
	sessionConn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: cannot open private session bus for XEmbed host: %v", err)
		return
	}
	if err := sessionConn.Auth(nil); err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host auth failed: %v", err)
		closeBus(sessionConn)
		return
	}
	if err := sessionConn.Hello(); err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host Hello failed: %v", err)
		closeBus(sessionConn)
		return
	}

	host, err := newXembedHost(sessionConn, busName, objPath)
	if err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host not started: %v", err)
		closeBus(sessionConn)
		return
	}

	w.hosts[busName] = host
	go host.run()
	log.Infof("StatusNotifierWatcher: XEmbed tray icon created for %s", busName)
}

// startStatusNotifierWatcher claims org.kde.StatusNotifierWatcher only as a
// bridge to an XEmbed tray on minimal WMs. The watcher is a stub that never
// relays items to a real StatusNotifierHost, so claiming the name on a desktop
// with a real host (e.g. Hyprland + Waybar) would dead-end every other tray
// app's icon. It gates on the actual presence of an XEmbed tray rather than
// GetNameOwner, which can't win a login-order race; without one it stays off
// the bus so the real watcher owns the name. The XEmbed tray may come up after
// the UI, so it re-probes for a grace period rather than deciding once.
// Safe to call unconditionally.
func startStatusNotifierWatcher() {
	go func() {
		deadline := time.Now().Add(watcherProbeTimeout)
		for {
			if xembedTrayAvailable() {
				claimStatusNotifierWatcher()
				return
			}
			if time.Now().After(deadline) {
				log.Debugf("StatusNotifierWatcher: no XEmbed tray appeared within %s, leaving the watcher to the desktop", watcherProbeTimeout)
				return
			}
			time.Sleep(watcherProbeInterval)
		}
	}()
}

// claimStatusNotifierWatcher takes ownership of org.kde.StatusNotifierWatcher
// on a private session bus and exports the stub watcher. The GetNameOwner /
// DoNotQueue guards back off if a real watcher already holds the name.
func claimStatusNotifierWatcher() {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: cannot open private session bus: %v", err)
		return
	}
	if err := conn.Auth(nil); err != nil {
		log.Debugf("StatusNotifierWatcher: auth failed: %v", err)
		closeBus(conn)
		return
	}
	if err := conn.Hello(); err != nil {
		log.Debugf("StatusNotifierWatcher: Hello failed: %v", err)
		closeBus(conn)
		return
	}

	var owner string
	callErr := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, watcherName).Store(&owner)
	if callErr == nil && owner != "" {
		log.Debugf("StatusNotifierWatcher: already owned by %s, skipping", owner)
		closeBus(conn)
		return
	}

	reply, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Debugf("StatusNotifierWatcher: could not claim name (reply=%v err=%v)", reply, err)
		closeBus(conn)
		return
	}

	w := &statusNotifierWatcher{
		conn:  conn,
		hosts: make(map[string]*xembedHost),
	}
	if err := conn.ExportAll(w, dbus.ObjectPath(watcherPath), watcherIface); err != nil {
		log.Errorf("StatusNotifierWatcher: export failed: %v", err)
		closeBus(conn)
		return
	}

	log.Infof("StatusNotifierWatcher: active on session bus (enables tray on minimal WMs)")
	// Connection kept open for the process lifetime.
}

// closeBus closes a private session bus opened on a back-off path, logging a
// warning rather than swallowing the error.
func closeBus(conn *dbus.Conn) {
	if err := conn.Close(); err != nil {
		log.Warnf("StatusNotifierWatcher: closing session bus failed: %v", err)
	}
}
