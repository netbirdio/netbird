//go:build linux && !(linux && 386)

package main

/*
#cgo pkg-config: x11 gtk+-3.0
#cgo LDFLAGS: -lX11
#include "xembed_tray.h"
#include <X11/Xlib.h>
#include <stdlib.h>
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

//export goMenuItemClicked
func goMenuItemClicked(id C.int) {
	activeMenuHostMu.Lock()
	h := activeMenuHost
	activeMenuHostMu.Unlock()

	if h != nil {
		go h.sendMenuEvent(int32(id))
	}
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

// newXembedHost creates an XEmbed tray icon for the given SNI item.
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
				log.Infof("xembed: right-click at (%d, %d)", int(outX), int(outY))
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
	log.Infof("xembed: menu has %d items (revision %d)", len(items), revision)
	for i, mi := range items {
		log.Infof("xembed: menu[%d] id=%d label=%q sep=%v check=%v", i, mi.id, mi.label, mi.isSeparator, mi.isCheck)
	}
	if len(items) == 0 {
		return
	}

	// Build C menu item array.
	cItems := make([]C.xembed_menu_item, len(items))
	cLabels := make([]*C.char, len(items)) // track for freeing
	for i, mi := range items {
		cItems[i].id = C.int(mi.id)
		cItems[i].enabled = boolToInt(mi.enabled)
		cItems[i].is_check = boolToInt(mi.isCheck)
		cItems[i].checked = boolToInt(mi.checked)
		cItems[i].is_separator = boolToInt(mi.isSeparator)
		if mi.label != "" {
			cLabels[i] = C.CString(mi.label)
			cItems[i].label = cLabels[i]
		}
	}
	defer func() {
		for _, p := range cLabels {
			if p != nil {
				C.free(unsafe.Pointer(p))
			}
		}
	}()

	// Set the active menu host so the C callback can reach us.
	activeMenuHostMu.Lock()
	activeMenuHost = h
	activeMenuHostMu.Unlock()

	C.xembed_show_popup_menu(&cItems[0], C.int(len(cItems)),
		nil, C.int(x), C.int(y))
}

// dbusMenuLayout represents a com.canonical.dbusmenu layout item.
type dbusMenuLayout struct {
	ID         int32
	Properties map[string]dbus.Variant
	Children   []dbus.Variant
}

type menuItemInfo struct {
	id          int32
	label       string
	enabled     bool
	isCheck     bool
	checked     bool
	isSeparator bool
}

func (h *xembedHost) flattenMenu(layout dbusMenuLayout) []menuItemInfo {
	var items []menuItemInfo

	for _, childVar := range layout.Children {
		var child dbusMenuLayout
		if err := dbus.Store([]interface{}{childVar.Value()}, &child); err != nil {
			continue
		}

		mi := menuItemInfo{
			id:      child.ID,
			enabled: true,
		}

		if v, ok := child.Properties["type"]; ok {
			if s, ok := v.Value().(string); ok && s == "separator" {
				mi.isSeparator = true
				items = append(items, mi)
				continue
			}
		}

		if v, ok := child.Properties["label"]; ok {
			if s, ok := v.Value().(string); ok {
				mi.label = s
			}
		}

		if v, ok := child.Properties["enabled"]; ok {
			if b, ok := v.Value().(bool); ok {
				mi.enabled = b
			}
		}

		if v, ok := child.Properties["visible"]; ok {
			if b, ok := v.Value().(bool); ok && !b {
				continue // skip hidden items
			}
		}

		if v, ok := child.Properties["toggle-type"]; ok {
			if s, ok := v.Value().(string); ok && s == "checkmark" {
				mi.isCheck = true
			}
		}

		if v, ok := child.Properties["toggle-state"]; ok {
			if n, ok := v.Value().(int32); ok && n == 1 {
				mi.checked = true
			}
		}

		items = append(items, mi)
	}

	return items
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

func boolToInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
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
