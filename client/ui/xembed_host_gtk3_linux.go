//go:build linux && gtk3 && !(linux && 386)

package main

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

// The legacy GTK3 / WebKit2GTK 4.1 build (-tags gtk3) drops the in-process
// XEmbed StatusNotifierWatcher entirely. The real implementation
// (xembed_host_linux.go + xembed_tray_linux.c) links GTK4 and uses GTK4-only
// popup-menu APIs that have no drop-in GTK3 equivalent, so rather than port the
// C layer we stub the host out on gtk3 builds. The tray still works on every
// desktop that ships its own StatusNotifierWatcher (KDE, GNOME+AppIndicator,
// Cinnamon/xapp, XFCE, …); only the minimal-WM fallback (Fluxbox/OpenBox/i3/
// dwm/vanilla GNOME) is unavailable on gtk3 packages. See LINUX-TRAY.md.

// xembedHost is a placeholder so the package compiles on gtk3 builds; the real
// type (with X11/GTK4 state) lives in xembed_host_linux.go. It is never
// instantiated here because xembedTrayAvailable always reports false.
type xembedHost struct{}

// run satisfies the call in tray_watcher_linux.go; unreachable on gtk3 because
// newXembedHost never returns a non-nil host.
func (*xembedHost) run() {}

// xembedTrayAvailable always reports false on gtk3 builds, so the watcher probe
// loop in startStatusNotifierWatcher exits immediately and newXembedHost is
// never reached. recenter_linux.go's predicate becomes a harmless no-op too.
func xembedTrayAvailable() bool {
	return false
}

// newXembedHost exists only to satisfy the reference in tray_watcher_linux.go;
// it is unreachable because xembedTrayAvailable returns false on gtk3.
func newXembedHost(conn *dbus.Conn, busName string, objPath dbus.ObjectPath) (*xembedHost, error) {
	return nil, errors.New("xembed host unsupported on gtk3 build")
}
