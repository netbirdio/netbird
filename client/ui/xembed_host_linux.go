//go:build linux && !(linux && 386)

package main

/*
#cgo pkg-config: x11 gtk4 gtk4-x11 cairo cairo-xlib
#cgo LDFLAGS: -lX11
#include "xembed_tray_linux.h"
#include <X11/Xlib.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

// activeMenuHost is the xembedHost that currently owns the popup menu.
// This is needed because C callbacks cannot carry Go pointers.
var (
	activeMenuHost   *xembedHost
	activeMenuHostMu sync.Mutex
)

// menuItemInfo is the Go-side representation of one popup menu entry,
// flattened from a dbusMenuLayout tree before it is handed to the C
// popup builder. Submenus populate children; leaves leave it nil.
type menuItemInfo struct {
	id          int32
	label       string
	enabled     bool
	isCheck     bool
	checked     bool
	isSeparator bool
	children    []menuItemInfo
}

// dbusMenuLayout mirrors the (ia{sv}av) result returned by
// com.canonical.dbusmenu.GetLayout. The Children variants each wrap a
// nested dbusMenuLayout; we decode them lazily in flattenMenu.
type dbusMenuLayout struct {
	ID         int32
	Properties map[string]dbus.Variant
	Children   []dbus.Variant
}

// xembedHost manages one XEmbed tray icon for an SNI item.
type xembedHost struct {
	conn    *dbus.Conn
	busName string
	objPath dbus.ObjectPath

	dpy      *C.Display
	trayMgr  C.Window
	iconWin  C.Window
	iconSize int

	mu       sync.Mutex
	iconData []byte
	iconW    int
	iconH    int

	stopCh chan struct{}
}

// goMenuItemClicked is the C callback invoked from the GTK main thread
// when the user activates a popup-menu entry. C callbacks cannot carry
// Go pointers, so the active xembedHost is looked up through the
// activeMenuHost global instead. //export makes this symbol visible to
// the C side; the function must therefore live in package main.
//
//export goMenuItemClicked
func goMenuItemClicked(id C.int) {
	activeMenuHostMu.Lock()
	h := activeMenuHost
	activeMenuHostMu.Unlock()

	if h != nil {
		go h.sendMenuEvent(int32(id))
	}
}

// newXembedHost creates an XEmbed tray icon for the given SNI item.
// xembedTrayAvailable reports whether an XEmbed system tray manager
// (_NET_SYSTEM_TRAY_S0) currently owns its selection on the default screen.
// It is a cheap, side-effect-free probe — it only queries the selection
// owner, creating no windows. Used to decide whether the in-process
// StatusNotifierWatcher is needed at all: the watcher exists solely to
// bridge SNI items into an XEmbed tray on minimal WMs, so when no XEmbed
// tray is present (e.g. Wayland compositors with a real SNI host like
// Waybar) we must not claim org.kde.StatusNotifierWatcher and shadow the
// real one. Returns false when there is no X display (pure Wayland).
func xembedTrayAvailable() bool {
	dpy := C.XOpenDisplay(nil)
	if dpy == nil {
		return false
	}
	defer C.XCloseDisplay(dpy)
	screen := C.xembed_default_screen(dpy)
	return C.xembed_find_tray(dpy, screen) != 0
}

// Returns an error if no XEmbed tray manager is available (graceful fallback).
func newXembedHost(conn *dbus.Conn, busName string, objPath dbus.ObjectPath) (*xembedHost, error) {
	dpy := C.XOpenDisplay(nil)
	if dpy == nil {
		return nil, errors.New("cannot open X display")
	}

	screen := C.xembed_default_screen(dpy)
	trayMgr := C.xembed_find_tray(dpy, screen)
	if trayMgr == 0 {
		C.XCloseDisplay(dpy)
		return nil, errors.New("no XEmbed system tray found")
	}

	// Query the tray manager's preferred icon size.
	iconSize := int(C.xembed_get_icon_size(dpy, trayMgr))
	if iconSize <= 0 {
		iconSize = 24 // fallback
	}

	iconWin := C.xembed_create_icon(dpy, screen, C.int(iconSize), trayMgr)
	if iconWin == 0 {
		C.XCloseDisplay(dpy)
		return nil, errors.New("failed to create icon window")
	}

	if C.xembed_dock(dpy, trayMgr, iconWin) != 0 {
		C.xembed_destroy_icon(dpy, iconWin)
		C.XCloseDisplay(dpy)
		return nil, errors.New("failed to dock icon")
	}

	h := &xembedHost{
		conn:     conn,
		busName:  busName,
		objPath:  objPath,
		dpy:      dpy,
		trayMgr:  trayMgr,
		iconWin:  iconWin,
		iconSize: iconSize,
		stopCh:   make(chan struct{}),
	}

	h.fetchAndDrawIcon()
	return h, nil
}

// fetchAndDrawIcon reads IconPixmap from the SNI item via D-Bus and draws it.
func (h *xembedHost) fetchAndDrawIcon() {
	obj := h.conn.Object(h.busName, h.objPath)
	variant, err := obj.GetProperty("org.kde.StatusNotifierItem.IconPixmap")
	if err != nil {
		log.Debugf("xembed: failed to get IconPixmap: %v", err)
		return
	}

	// IconPixmap is []struct{W, H int32; Pix []byte} on D-Bus,
	// represented as a(iiay) signature.
	type px struct {
		W   int32
		H   int32
		Pix []byte
	}

	var icons []px
	if err := variant.Store(&icons); err != nil {
		log.Debugf("xembed: failed to decode IconPixmap: %v", err)
		return
	}

	if len(icons) == 0 {
		log.Debug("xembed: IconPixmap is empty")
		return
	}

	icon := icons[0]
	if icon.W <= 0 || icon.H <= 0 || len(icon.Pix) < int(icon.W*icon.H*4) {
		log.Debug("xembed: invalid IconPixmap data")
		return
	}

	h.mu.Lock()
	h.iconData = icon.Pix
	h.iconW = int(icon.W)
	h.iconH = int(icon.H)
	h.mu.Unlock()

	h.drawIcon()
}

// drawIcon draws the cached icon data onto the X11 window.
func (h *xembedHost) drawIcon() {
	h.mu.Lock()
	data := h.iconData
	w := h.iconW
	ht := h.iconH
	h.mu.Unlock()

	if data == nil || w <= 0 || ht <= 0 {
		return
	}

	cData := C.CBytes(data)
	defer C.free(cData)

	C.xembed_draw_icon(h.dpy, h.iconWin, C.int(h.iconSize),
		(*C.uchar)(cData), C.int(w), C.int(ht))
}

// run is the main event loop. It polls X11 events and listens for D-Bus
// NewIcon signals to keep the tray icon updated.
func (h *xembedHost) run() {
	// Subscribe to NewIcon signals from the SNI item.
	matchRule := "type='signal',interface='org.kde.StatusNotifierItem',member='NewIcon',sender='" + h.busName + "'"
	if err := h.conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err; err != nil {
		log.Debugf("xembed: failed to add signal match: %v", err)
	}

	sigCh := make(chan *dbus.Signal, 16)
	h.conn.Signal(sigCh)
	defer h.conn.RemoveSignal(sigCh)

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return

		case sig := <-sigCh:
			if sig == nil {
				continue
			}
			if sig.Name == "org.kde.StatusNotifierItem.NewIcon" {
				h.fetchAndDrawIcon()
			}

		case <-ticker.C:
			var outX, outY C.int
			result := C.xembed_poll_event(h.dpy, h.iconWin, &outX, &outY)

			switch result {
			case 1: // left click
				go h.activate(int32(outX), int32(outY))
			case 2: // right click
				go h.contextMenu(int32(outX), int32(outY))
			case 3: // expose
				h.drawIcon()
			case 4: // configure (resize)
				newSize := int(outX)
				if newSize > 0 && newSize != h.iconSize {
					h.iconSize = newSize
					h.drawIcon()
				}
			case -1: // tray died
				log.Info("xembed: tray manager destroyed, cleaning up")
				return
			}
		}
	}
}

func (h *xembedHost) activate(x, y int32) {
	obj := h.conn.Object(h.busName, h.objPath)
	if err := obj.Call("org.kde.StatusNotifierItem.Activate", 0, x, y).Err; err != nil {
		log.Debugf("xembed: Activate call failed: %v", err)
	}
}

func (h *xembedHost) contextMenu(x, y int32) {
	// Read the menu path from the SNI item's Menu property.
	menuPath := dbus.ObjectPath("/StatusNotifierMenu")

	// Fetch menu layout from com.canonical.dbusmenu.
	menuObj := h.conn.Object(h.busName, menuPath)
	var revision uint32
	var layout dbusMenuLayout
	err := menuObj.Call("com.canonical.dbusmenu.GetLayout", 0,
		int32(0),   // parentId (root)
		int32(-1),  // recursionDepth (all)
		[]string{}, // propertyNames (all)
	).Store(&revision, &layout)
	if err != nil {
		log.Debugf("xembed: GetLayout failed: %v", err)
		return
	}

	items := h.flattenMenu(layout)
	log.Debugf("xembed: menu has %d items (revision %d)", len(items), revision)
	if len(items) == 0 {
		return
	}

	// Build a C-allocated tree from the Go menu. xembed_show_popup_menu
	// deep-copies into its own buffer (so it can outlive this stack
	// frame), but it expects valid C strings + pointers in the caller's
	// array — we still have to walk the items on the Go side and build
	// matching C.xembed_menu_item nodes recursively.
	var allocs []unsafe.Pointer
	cItems := buildCItems(items, &allocs)
	defer func() {
		for _, p := range allocs {
			C.free(p)
		}
	}()

	// Set the active menu host so the C callback can reach us.
	activeMenuHostMu.Lock()
	activeMenuHost = h
	activeMenuHostMu.Unlock()

	C.xembed_show_popup_menu(cItems, C.int(len(items)),
		nil, C.int(x), C.int(y))
}

func (h *xembedHost) flattenMenu(layout dbusMenuLayout) []menuItemInfo {
	var items []menuItemInfo

	for _, childVar := range layout.Children {
		var child dbusMenuLayout
		if err := dbus.Store([]interface{}{childVar.Value()}, &child); err != nil {
			continue
		}
		if mi, ok := h.menuItemFromLayout(child); ok {
			items = append(items, mi)
		}
	}

	return items
}

// menuItemFromLayout decodes one dbusmenu child node into a menuItemInfo,
// recursing into submenus. The bool return is false when the item is hidden
// (visible=false) and should be dropped from the parent's list.
func (h *xembedHost) menuItemFromLayout(child dbusMenuLayout) (menuItemInfo, bool) {
	mi := menuItemInfo{id: child.ID, enabled: true}

	if propString(child.Properties, "type") == "separator" {
		mi.isSeparator = true
		return mi, true
	}

	if vis, ok := propBool(child.Properties, "visible"); ok && !vis {
		return menuItemInfo{}, false
	}

	mi.label = propString(child.Properties, "label")
	if en, ok := propBool(child.Properties, "enabled"); ok {
		mi.enabled = en
	}
	if propString(child.Properties, "toggle-type") == "checkmark" {
		mi.isCheck = true
	}
	if n, ok := propInt32(child.Properties, "toggle-state"); ok && n == 1 {
		mi.checked = true
	}

	// Recurse into nested submenus. The dbusmenu spec marks a folder
	// item with children-display=="submenu"; the children are already
	// in child.Children because GetLayout was called with
	// recursionDepth=-1 (all levels).
	if propString(child.Properties, "children-display") == "submenu" {
		mi.children = h.flattenMenu(child)
	}

	return mi, true
}

func (h *xembedHost) sendMenuEvent(id int32) {
	menuPath := dbus.ObjectPath("/StatusNotifierMenu")
	menuObj := h.conn.Object(h.busName, menuPath)
	data := dbus.MakeVariant("")
	err := menuObj.Call("com.canonical.dbusmenu.Event", 0,
		id, "clicked", data, uint32(0)).Err
	if err != nil {
		log.Debugf("xembed: menu Event call failed: %v", err)
	}
}

func (h *xembedHost) stop() {
	select {
	case <-h.stopCh:
		return // already stopped
	default:
		close(h.stopCh)
	}

	C.xembed_destroy_icon(h.dpy, h.iconWin)
	C.XCloseDisplay(h.dpy)
}

// buildCItems recursively translates Go menuItemInfo slices into a
// C-allocated array of xembed_menu_item suitable for passing across the
// Cgo boundary. The C side deep-copies the structure when it stages
// the popup, so any transient labels/children we allocate here can be
// released as soon as xembed_show_popup_menu returns. Every malloc is
// recorded in *allocs so the caller can free it via a single deferred
// loop. Returns nil for empty slices.
func buildCItems(items []menuItemInfo, allocs *[]unsafe.Pointer) *C.xembed_menu_item {
	if len(items) == 0 {
		return nil
	}
	size := C.size_t(len(items)) * C.size_t(unsafe.Sizeof(C.xembed_menu_item{}))
	arr := C.malloc(size)
	*allocs = append(*allocs, arr)
	C.memset(arr, 0, size)

	slice := (*[1 << 16]C.xembed_menu_item)(arr)[:len(items):len(items)]
	for i, mi := range items {
		slice[i].id = C.int(mi.id)
		slice[i].enabled = boolToInt(mi.enabled)
		slice[i].is_check = boolToInt(mi.isCheck)
		slice[i].checked = boolToInt(mi.checked)
		slice[i].is_separator = boolToInt(mi.isSeparator)
		if mi.label != "" {
			cstr := C.CString(mi.label)
			*allocs = append(*allocs, unsafe.Pointer(cstr))
			slice[i].label = cstr
		}
		if len(mi.children) > 0 {
			slice[i].children = buildCItems(mi.children, allocs)
			slice[i].child_count = C.int(len(mi.children))
		}
	}

	return (*C.xembed_menu_item)(arr)
}

// boolToInt converts a Go bool to the C int the dbusmenu C API uses
// for boolean flags.
func boolToInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// propString returns the string value of a dbusmenu property, or "" when the
// property is absent or not a string.
func propString(props map[string]dbus.Variant, key string) string {
	if v, ok := props[key]; ok {
		if s, ok := v.Value().(string); ok {
			return s
		}
	}
	return ""
}

// propBool returns the bool value of a dbusmenu property; ok is false when the
// property is absent or not a bool.
func propBool(props map[string]dbus.Variant, key string) (value, ok bool) {
	if v, present := props[key]; present {
		if b, isBool := v.Value().(bool); isBool {
			return b, true
		}
	}
	return false, false
}

// propInt32 returns the int32 value of a dbusmenu property; ok is false when
// the property is absent or not an int32.
func propInt32(props map[string]dbus.Variant, key string) (value int32, ok bool) {
	if v, present := props[key]; present {
		if n, isInt := v.Value().(int32); isInt {
			return n, true
		}
	}
	return 0, false
}
