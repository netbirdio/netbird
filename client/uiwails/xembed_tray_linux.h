#ifndef XEMBED_TRAY_H
#define XEMBED_TRAY_H

#include <X11/Xlib.h>

// xembed_default_screen wraps the DefaultScreen macro for CGo.
static inline int xembed_default_screen(Display *dpy) {
    return DefaultScreen(dpy);
}

// xembed_find_tray returns the selection owner window for
// _NET_SYSTEM_TRAY_S{screen}, or 0 if no XEmbed tray manager exists.
Window xembed_find_tray(Display *dpy, int screen);

// xembed_get_icon_size queries _NET_SYSTEM_TRAY_ICON_SIZE from the tray
// manager window. Returns the size in pixels, or 0 if not set.
int xembed_get_icon_size(Display *dpy, Window tray_mgr);

// xembed_create_icon creates a tray icon window of the given size,
// sets _XEMBED_INFO, and returns the window ID.
// tray_mgr is the tray manager window; its _NET_SYSTEM_TRAY_VISUAL
// property is queried to obtain a 32-bit ARGB visual for transparency.
Window xembed_create_icon(Display *dpy, int screen, int size, Window tray_mgr);

// xembed_dock sends _NET_SYSTEM_TRAY_OPCODE SYSTEM_TRAY_REQUEST_DOCK
// to the tray manager to embed our icon window.
int xembed_dock(Display *dpy, Window tray_mgr, Window icon_win);

// xembed_draw_icon draws ARGB pixel data onto the icon window.
// data is in [A,R,G,B] byte order per pixel (SNI IconPixmap format).
// img_w, img_h are the source image dimensions.
// win_size is the target window dimension (square).
void xembed_draw_icon(Display *dpy, Window icon_win, int win_size,
                      const unsigned char *data, int img_w, int img_h);

// xembed_destroy_icon destroys the icon window.
void xembed_destroy_icon(Display *dpy, Window icon_win);

// xembed_poll_event processes pending X11 events. Returns:
//   0 = no actionable event
//   1 = left button press (out_x, out_y filled)
//   2 = right button press (out_x, out_y filled)
//   3 = expose (needs redraw)
//   4 = configure (resize; out_x=width, out_y=height)
//  -1 = DestroyNotify on icon window (tray died)
int xembed_poll_event(Display *dpy, Window icon_win,
                      int *out_x, int *out_y);

// Callback type for menu item clicks. Called with the item's dbusmenu ID.
typedef void (*xembed_menu_click_cb)(int id);

// xembed_popup_menu builds and shows a GTK3 popup menu.
// items is an array of menu item descriptors, count is the number of items.
// cb is called (from the GTK main thread) when an item is clicked.
// x, y are root coordinates for positioning the popup.
// This must be called from the GTK main thread (use g_idle_add).

typedef struct {
    int    id;          // dbusmenu item ID
    const char *label;  // display label (NULL for separator)
    int    enabled;     // whether the item is clickable
    int    is_check;    // whether this is a checkbox item
    int    checked;     // checkbox state (0 or 1)
    int    is_separator;// 1 if this is a separator
} xembed_menu_item;

// Schedule a GTK popup menu on the main thread.
void xembed_show_popup_menu(xembed_menu_item *items, int count,
                            xembed_menu_click_cb cb, int x, int y);

#endif
