//go:build linux && !(linux && 386)

package main

// In-process org.kde.StatusNotifierWatcher for minimal WMs (Fluxbox, OpenBox,
// i3) that ship no watcher. When an XEmbed tray exists (_NET_SYSTEM_TRAY_S0),
// an in-process XEmbed host bridges the SNI icon into it.

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
	log "github.com/sirupsen/logrus"
)

const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = "/StatusNotifierWatcher"
	watcherIface = "org.kde.StatusNotifierWatcher"

	// Returned by GetNameOwner when the name is free, as opposed to a failure
	// that leaves the current owner unknown.
	nameHasNoOwnerError = "org.freedesktop.DBus.Error.NameHasNoOwner"

	// Fallback item path for clients that register by bus name.
	defaultItemPath = "/StatusNotifierItem"

	// The UI is often autostarted before the panel on minimal WMs, so a single
	// startup probe would miss a tray that appears a second later.
	watcherProbeInterval = 500 * time.Millisecond
	watcherProbeTimeout  = 10 * time.Second
)

// desktopsShippingWatcher holds XDG_CURRENT_DESKTOP values whose session
// provides its own StatusNotifierWatcher. GNOME is deliberately absent: without
// the AppIndicator extension it has none, and it is one of the fallback's
// targets.
var desktopsShippingWatcher = map[string]bool{
	"kde":        true,
	"plasma":     true,
	"x-cinnamon": true,
	"cinnamon":   true,
	"xfce":       true,
	"lxqt":       true,
	"mate":       true,
	"budgie":     true,
	"pantheon":   true,
	"deepin":     true,
	"unity":      true,
}

type statusNotifierWatcher struct {
	conn  *dbus.Conn
	props *prop.Properties

	itemsMu sync.Mutex
	items   []string

	hostsMu sync.Mutex
	hosts   map[string]*xembedHost
}

// RegisterStatusNotifierItem is the D-Bus method called by tray clients.
// sender is injected by godbus and is not part of the D-Bus signature.
func (w *statusNotifierWatcher) RegisterStatusNotifierItem(sender dbus.Sender, service string) *dbus.Error {
	id := itemID(sender, service)
	if w.addItem(id) {
		log.Debugf("StatusNotifierWatcher: registered item %q from %s", service, sender)

		if err := w.conn.Emit(watcherPath, watcherIface+".StatusNotifierItemRegistered", id); err != nil {
			log.Debugf("StatusNotifierWatcher: emitting StatusNotifierItemRegistered failed: %v", err)
		}
	}

	// Attempted on every call, not only the first: a client re-registers when
	// the watcher name changes owner, and that is the chance to host an item
	// again after its previous host lost the tray.
	go w.tryStartXembedHost(id, string(sender), itemObjectPath(service))
	return nil
}

// itemID identifies a registered item. A client may register by bus name or by
// object path, and clients that register by path mostly use the same well-known
// one, so the path form is qualified with the sender's unique name to keep two
// items from colliding.
func itemID(sender dbus.Sender, service string) string {
	if strings.HasPrefix(service, "/") {
		return string(sender) + service
	}
	return service
}

// addItem records the item and publishes the new list, reporting false when the
// item was already registered.
func (w *statusNotifierWatcher) addItem(service string) bool {
	w.itemsMu.Lock()
	defer w.itemsMu.Unlock()

	for _, s := range w.items {
		if s == service {
			return false
		}
	}
	w.items = append(w.items, service)

	// Published under the lock so concurrent registrations cannot leave the
	// property holding an older snapshot than the slice.
	w.props.SetMust(watcherIface, "RegisteredStatusNotifierItems", append([]string(nil), w.items...))
	return true
}

// itemObjectPath resolves the RegisterStatusNotifierItem argument to the item's
// object path. The SNI spec lets a client pass either its bus name or the
// object path: libappindicator sends the bus name, Qt sends the path. A bus
// name means the item sits at the well-known default path.
func itemObjectPath(service string) dbus.ObjectPath {
	if path := dbus.ObjectPath(service); strings.HasPrefix(service, "/") && path.IsValid() {
		return path
	}
	return defaultItemPath
}

// RegisterStatusNotifierHost is required by the protocol but unused here.
func (w *statusNotifierWatcher) RegisterStatusNotifierHost(service string) *dbus.Error {
	log.Debugf("StatusNotifierWatcher: host registered %q", service)
	if err := w.conn.Emit(watcherPath, watcherIface+".StatusNotifierHostRegistered"); err != nil {
		log.Debugf("StatusNotifierWatcher: emitting StatusNotifierHostRegistered failed: %v", err)
	}
	return nil
}

// tryStartXembedHost is a no-op when no XEmbed tray manager is available. The
// host is built outside hostsMu because newXembedHost blocks on a D-Bus
// round-trip to the item, and one unresponsive item must not hold up the rest.
func (w *statusNotifierWatcher) tryStartXembedHost(id, busName string, objPath dbus.ObjectPath) {
	if w.hasHost(id) {
		return
	}

	// Private session bus so our signal subscriptions don't reach Wails'
	// signal handler, which panics on unexpected signals.
	sessionConn, err := privateSessionBus()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: no session bus for XEmbed host: %v", err)
		return
	}

	host, err := newXembedHost(sessionConn, busName, objPath)
	if err != nil {
		log.Debugf("StatusNotifierWatcher: XEmbed host not started: %v", err)
		closeBus(sessionConn)
		return
	}

	if !w.addHost(id, host) {
		host.stop()
		closeBus(sessionConn)
		return
	}

	go func() {
		host.run()
		w.removeHost(id, host, sessionConn)
	}()
	log.Infof("StatusNotifierWatcher: XEmbed tray icon created for %s", id)
}

func (w *statusNotifierWatcher) hasHost(id string) bool {
	w.hostsMu.Lock()
	defer w.hostsMu.Unlock()

	_, exists := w.hosts[id]
	return exists
}

// addHost publishes the host, reporting false when a concurrent registration
// for the same item got there first.
func (w *statusNotifierWatcher) addHost(id string, host *xembedHost) bool {
	w.hostsMu.Lock()
	defer w.hostsMu.Unlock()

	if _, exists := w.hosts[id]; exists {
		return false
	}
	w.hosts[id] = host
	return true
}

// removeHost releases the host once its run loop has exited, which happens when
// the tray manager goes away. Dropping the entry lets the item be hosted again
// if it re-registers.
func (w *statusNotifierWatcher) removeHost(id string, host *xembedHost, conn *dbus.Conn) {
	w.hostsMu.Lock()
	if w.hosts[id] == host {
		delete(w.hosts, id)
	}
	w.hostsMu.Unlock()

	host.stop()
	closeBus(conn)
}

// startStatusNotifierWatcher claims org.kde.StatusNotifierWatcher only as a
// bridge to an XEmbed tray on minimal WMs. The watcher never relays items to a
// real StatusNotifierHost, so claiming the name on a desktop that has one would
// dead-end every other tray app's icon. Safe to call unconditionally.
func startStatusNotifierWatcher() {
	if desktop := desktopWithOwnWatcher(); desktop != "" {
		log.Debugf("StatusNotifierWatcher: %s provides a watcher, staying a plain SNI client", desktop)
		return
	}
	go awaitAndClaimWatcher()
}

// desktopWithOwnWatcher reports the XDG_CURRENT_DESKTOP entry whose session
// ships a StatusNotifierWatcher, or "" when none does. The variable is a
// colon-separated list, most specific first.
func desktopWithOwnWatcher() string {
	for _, desktop := range strings.Split(os.Getenv("XDG_CURRENT_DESKTOP"), ":") {
		if desktopsShippingWatcher[strings.ToLower(strings.TrimSpace(desktop))] {
			return desktop
		}
	}
	return ""
}

// awaitAndClaimWatcher waits out the whole probe window before claiming the
// name. Claiming as soon as an XEmbed tray appears loses the login race against
// a desktop watcher that starts in the session's panel phase: that watcher then
// finds the name taken and exits, leaving every SNI app in the session with
// nowhere to go. Waiting is free — the Wails systray re-registers its item on
// NameOwnerChanged, so our own icon still arrives once we claim.
func awaitAndClaimWatcher() {
	conn, err := privateSessionBus()
	if err != nil {
		log.Debugf("StatusNotifierWatcher: cannot open private session bus: %v", err)
		return
	}

	trayFound := false
	deadline := time.Now().Add(watcherProbeTimeout)
	for {
		if owner, unowned := watcherOwner(conn); !unowned {
			log.Debugf("StatusNotifierWatcher: name not free (owner=%q), staying a plain SNI client", owner)
			closeBus(conn)
			return
		}
		trayFound = trayFound || xembedTrayAvailable()

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(watcherProbeInterval)
	}

	if !trayFound {
		log.Debugf("StatusNotifierWatcher: no XEmbed tray within %s, leaving the watcher to the desktop", watcherProbeTimeout)
		closeBus(conn)
		return
	}

	claimStatusNotifierWatcher(conn)
}

// watcherOwner reports the current owner of org.kde.StatusNotifierWatcher.
// unowned is true only when the bus positively says the name is free: a lookup
// that fails for any other reason leaves the owner unknown, and the caller must
// not read that as an invitation to claim the name.
func watcherOwner(conn *dbus.Conn) (owner string, unowned bool) {
	err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, watcherName).Store(&owner)
	if err == nil {
		return owner, false
	}

	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) && dbusErr.Name == nameHasNoOwnerError {
		return "", true
	}

	log.Debugf("StatusNotifierWatcher: GetNameOwner failed: %v", err)
	return "", false
}

// claimStatusNotifierWatcher takes ownership of the name on conn and exports
// the watcher. conn is consumed: it is closed on failure, and kept open for the
// process lifetime on success so the name stays held.
func claimStatusNotifierWatcher(conn *dbus.Conn) {
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

	// Clients introspect the watcher's properties before they trust it, so the
	// spec's three read-only properties have to be readable through
	// org.freedesktop.DBus.Properties, which godbus does not export by itself.
	w.props, err = prop.Export(conn, watcherPath, prop.Map{
		watcherIface: {
			"RegisteredStatusNotifierItems":  {Value: []string{}, Emit: prop.EmitTrue},
			"IsStatusNotifierHostRegistered": {Value: true, Emit: prop.EmitTrue},
			"ProtocolVersion":                {Value: int32(0), Emit: prop.EmitConst},
		},
	})
	if err != nil {
		log.Errorf("StatusNotifierWatcher: exporting properties failed: %v", err)
		closeBus(conn)
		return
	}

	if err := conn.ExportAll(w, dbus.ObjectPath(watcherPath), watcherIface); err != nil {
		log.Errorf("StatusNotifierWatcher: export failed: %v", err)
		closeBus(conn)
		return
	}

	log.Infof("StatusNotifierWatcher: active on session bus (enables tray on minimal WMs)")
}

// privateSessionBus opens an authenticated private session bus, so signal
// subscriptions on it stay out of the shared connection's handlers.
func privateSessionBus() (*dbus.Conn, error) {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, err
	}
	if err := conn.Auth(nil); err != nil {
		closeBus(conn)
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		closeBus(conn)
		return nil, err
	}
	return conn, nil
}

// closeBus closes a private session bus opened on a back-off path, logging a
// warning rather than swallowing the error.
func closeBus(conn *dbus.Conn) {
	if err := conn.Close(); err != nil {
		log.Warnf("StatusNotifierWatcher: closing session bus failed: %v", err)
	}
}
