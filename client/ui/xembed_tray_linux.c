#include "xembed_tray_linux.h"

#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <cairo/cairo-xlib.h>
#include <cairo/cairo.h>
#include <gtk/gtk.h>
#include <gdk/x11/gdkx.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SYSTEM_TRAY_REQUEST_DOCK 0
#define XEMBED_MAPPED            (1 << 0)

/* Xlib's default protocol-error handler calls exit() on any async X error,
   killing the whole UI process. Handlers are process-global (not
   per-Display), so a single install covers our raw tray Display and GDK's.
   Tray work is full of races the X server reports asynchronously — the tray
   manager window dying between xembed_find_tray and xembed_dock (BadWindow
   on XSendEvent), or x11_move_window touching a popup the WM already
   destroyed — and the default handler would take us down for any of them.
   Returning 0 here makes the error a logged no-op instead. */
static int xembed_x_error_handler(Display *dpy, XErrorEvent *ev) {
    char buf[256];
    XGetErrorText(dpy, ev->error_code, buf, sizeof(buf));
    fprintf(stderr,
            "xembed: X error (ignored): %s (code=%d, request=%d.%d, resource=0x%lx)\n",
            buf, ev->error_code, ev->request_code, ev->minor_code,
            ev->resourceid);
    return 0;
}

/* The I/O error handler fires when the X connection itself drops (server
   gone, socket closed). Xlib treats this as fatal and exits even if we
   return, so this can't keep the process alive — it only logs a clearer
   line than Xlib's terse default before the unavoidable exit. */
static int xembed_x_io_error_handler(Display *dpy) {
    (void)dpy;
    fprintf(stderr, "xembed: X I/O error (connection lost)\n");
    return 0;
}

/* Install the process-global handlers. Idempotent and cheap, so callers may
   invoke it after every XOpenDisplay without tracking prior installs. */
void xembed_install_error_handlers(void) {
    XSetErrorHandler(xembed_x_error_handler);
    XSetIOErrorHandler(xembed_x_io_error_handler);
}

Window xembed_find_tray(Display *dpy, int screen) {
    char atom_name[64];
    snprintf(atom_name, sizeof(atom_name), "_NET_SYSTEM_TRAY_S%d", screen);
    Atom sel = XInternAtom(dpy, atom_name, False);
    return XGetSelectionOwner(dpy, sel);
}

int xembed_get_icon_size(Display *dpy, Window tray_mgr) {
    Atom atom = XInternAtom(dpy, "_NET_SYSTEM_TRAY_ICON_SIZE", False);
    Atom actual_type;
    int actual_format;
    unsigned long nitems, bytes_after;
    unsigned char *prop = NULL;
    int size = 0;

    if (XGetWindowProperty(dpy, tray_mgr, atom, 0, 1, False,
                           XA_CARDINAL, &actual_type, &actual_format,
                           &nitems, &bytes_after, &prop) == Success) {
        if (prop && nitems == 1 && actual_format == 32) {
            size = (int)(*(unsigned long *)prop);
        }
        if (prop)
            XFree(prop);
    }
    return size;
}

Window xembed_create_icon(Display *dpy, int screen, int size,
                           Window tray_mgr) {
    (void)tray_mgr;  /* unused; kept in signature for caller symmetry */
    Window root = RootWindow(dpy, screen);

    /* Inherit visual & depth from the parent (tray manager / root) so
       ParentRelative background works on every tray. Many minimal
       toolbars (Fluxbox slit, OpenBox, etc.) only offer a 24-bit
       default visual and do not composite alpha; ParentRelative makes
       the X server texture this window's background from the parent,
       so transparent pixels in the icon show the toolbar beneath
       instead of solid black. ARGB-aware trays still work because the
       cairo OVER blend in xembed_draw_icon honours per-pixel alpha
       against whatever base the X server painted underneath. */
    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.event_mask = ButtonPressMask | StructureNotifyMask | ExposureMask;
    attrs.background_pixmap = ParentRelative;
    unsigned long mask = CWEventMask | CWBackPixmap;

    Window win = XCreateWindow(
        dpy, root,
        0, 0, size, size,
        0,                          /* border width */
        CopyFromParent,             /* depth */
        InputOutput,
        CopyFromParent,             /* visual */
        mask,
        &attrs
    );

    /* Set _XEMBED_INFO: version=0, flags=XEMBED_MAPPED */
    Atom xembed_info = XInternAtom(dpy, "_XEMBED_INFO", False);
    unsigned long info[2] = { 0, XEMBED_MAPPED };
    XChangeProperty(dpy, win, xembed_info, xembed_info,
                    32, PropModeReplace, (unsigned char *)info, 2);

    return win;
}

int xembed_dock(Display *dpy, Window tray_mgr, Window icon_win) {
    Atom opcode = XInternAtom(dpy, "_NET_SYSTEM_TRAY_OPCODE", False);

    XClientMessageEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.type         = ClientMessage;
    ev.window       = tray_mgr;
    ev.message_type = opcode;
    ev.format       = 32;
    ev.data.l[0]    = CurrentTime;
    ev.data.l[1]    = SYSTEM_TRAY_REQUEST_DOCK;
    ev.data.l[2]    = (long)icon_win;

    XSendEvent(dpy, tray_mgr, False, NoEventMask, (XEvent *)&ev);
    XFlush(dpy);
    return 0;
}

void xembed_draw_icon(Display *dpy, Window icon_win, int win_size,
                      const unsigned char *data, int img_w, int img_h) {
    if (!data || img_w <= 0 || img_h <= 0 || win_size <= 0)
        return;

    /* Query the window's actual visual and depth so cairo composites
       through the matching ARGB pipeline. */
    XWindowAttributes wa;
    if (!XGetWindowAttributes(dpy, icon_win, &wa))
        return;

    /* Build a CAIRO_FORMAT_ARGB32 source surface from the SNI IconPixmap
       bytes. SNI ships the pixels as [A,R,G,B,...] in network byte
       order; cairo's ARGB32 stores native uint32 with B in the lowest
       byte on little-endian hosts. Repack into native order with
       pre-multiplied alpha so cairo can composite without tonemapping. */
    int stride = cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32, img_w);
    unsigned char *buf = (unsigned char *)calloc(stride * img_h, 1);
    if (!buf)
        return;

    for (int y = 0; y < img_h; y++) {
        unsigned int *row = (unsigned int *)(buf + y * stride);
        for (int x = 0; x < img_w; x++) {
            int idx = (y * img_w + x) * 4;
            unsigned int a = data[idx + 0];
            unsigned int r = data[idx + 1];
            unsigned int g = data[idx + 2];
            unsigned int b = data[idx + 3];

            if (a == 0) {
                row[x] = 0;
            } else if (a == 255) {
                row[x] = (a << 24) | (r << 16) | (g << 8) | b;
            } else {
                unsigned int pr = r * a / 255;
                unsigned int pg = g * a / 255;
                unsigned int pb = b * a / 255;
                row[x] = (a << 24) | (pr << 16) | (pg << 8) | pb;
            }
        }
    }

    cairo_surface_t *src = cairo_image_surface_create_for_data(
        buf, CAIRO_FORMAT_ARGB32, img_w, img_h, stride);
    if (cairo_surface_status(src) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(src);
        free(buf);
        return;
    }

    /* Wrap the X11 window in a cairo XLib surface using its real visual. */
    cairo_surface_t *dst = cairo_xlib_surface_create(
        dpy, icon_win, wa.visual, win_size, win_size);
    if (cairo_surface_status(dst) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(dst);
        cairo_surface_destroy(src);
        free(buf);
        return;
    }

    /* Repaint the ParentRelative background first — without this the
       window keeps the previously-drawn icon underneath when an icon
       update arrives, and cairo's OVER blend would composite the new
       icon on top of the stale one. XClearWindow forces the X server
       to retexture from the parent (tray toolbar), giving us a clean
       opaque base. */
    XClearWindow(dpy, icon_win);

    cairo_t *cr = cairo_create(dst);

    /* Scale the source onto the window with alpha compositing (default
       OPERATOR_OVER). Transparent pixels keep the toolbar's pixels
       visible underneath. */
    double sx = (double)win_size / img_w;
    double sy = (double)win_size / img_h;
    cairo_scale(cr, sx, sy);
    cairo_set_source_surface(cr, src, 0, 0);
    cairo_paint(cr);

    cairo_destroy(cr);
    cairo_surface_destroy(dst);
    cairo_surface_destroy(src);
    free(buf);
    XFlush(dpy);
}

void xembed_destroy_icon(Display *dpy, Window icon_win) {
    if (icon_win)
        XDestroyWindow(dpy, icon_win);
    XFlush(dpy);
}

int xembed_poll_event(Display *dpy, Window icon_win,
                      int *out_x, int *out_y) {
    *out_x = 0;
    *out_y = 0;

    while (XPending(dpy) > 0) {
        XEvent ev;
        XNextEvent(dpy, &ev);

        switch (ev.type) {
        case ButtonPress:
            if (ev.xbutton.window == icon_win) {
                *out_x = ev.xbutton.x_root;
                *out_y = ev.xbutton.y_root;
                if (ev.xbutton.button == Button1)
                    return 1;
                if (ev.xbutton.button == Button3)
                    return 2;
            }
            break;

        case Expose:
            if (ev.xexpose.window == icon_win && ev.xexpose.count == 0)
                return 3;
            break;

        case DestroyNotify:
            if (ev.xdestroywindow.window == icon_win)
                return -1;
            break;

        case ConfigureNotify:
            if (ev.xconfigure.window == icon_win) {
                *out_x = ev.xconfigure.width;
                *out_y = ev.xconfigure.height;
                return 4;
            }
            break;

        case ReparentNotify:
            /* Tray manager reparented us — this is expected after docking. */
            break;

        default:
            break;
        }
    }

    return 0;
}

/* --- GTK4 popup window menu support --- */

/* Implemented in Go via //export */
extern void goMenuItemClicked(int id);

/* The top-level popup window, reused across invocations. Submenu
   popups are tracked in a separate list so they all close when the
   top-level closes. */
static GtkWidget *popup_win = NULL;
static GList     *submenu_popups = NULL;  /* list of GtkWidget* */

typedef struct {
    xembed_menu_item  *items;
    int                count;
    int                x, y;
} popup_data;

/* Deep-free a heap-owned xembed_menu_item array (label + children). */
static void free_items(xembed_menu_item *items, int count) {
    if (!items) return;
    for (int i = 0; i < count; i++) {
        free((void *)items[i].label);
        free_items(items[i].children, items[i].child_count);
    }
    free(items);
}

static void free_popup_data(popup_data *pd) {
    if (!pd) return;
    free_items(pd->items, pd->count);
    free(pd);
}


/* Close every popup window — top-level plus any open submenus.
   Called when the user clicks an actionable item or focus leaves the
   menu tree. */
static void close_all_popups(void) {
    for (GList *l = submenu_popups; l; l = l->next) {
        gtk_window_destroy(GTK_WINDOW(l->data));
    }
    g_list_free(submenu_popups);
    submenu_popups = NULL;

    if (popup_win) {
        gtk_widget_set_visible(popup_win, FALSE);
    }
}

static void on_button_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    int id = GPOINTER_TO_INT(user_data);
    close_all_popups();
    goMenuItemClicked(id);
}

static void on_check_toggled(GtkCheckButton *btn, gpointer user_data) {
    (void)btn;
    int id = GPOINTER_TO_INT(user_data);
    close_all_popups();
    goMenuItemClicked(id);
}

/* The popup is a regular WM-managed window (not override-redirect),
   so the WM hands keyboard focus to it on map. When focus moves
   elsewhere — the user clicked somewhere else, switched apps, etc. —
   the focus controller's "leave" signal fires and we tear down the
   menu tree. Submenus open from inside the top-level popup, so we
   defer the actual close to an idle callback: that gives the new
   submenu a chance to take focus first, and we only close if none of
   our windows still has it. */
static gboolean any_popup_has_focus(void) {
    if (popup_win && gtk_window_is_active(GTK_WINDOW(popup_win)))
        return TRUE;
    for (GList *l = submenu_popups; l; l = l->next) {
        if (gtk_window_is_active(GTK_WINDOW(l->data)))
            return TRUE;
    }
    return FALSE;
}

static gboolean focus_out_recheck(gpointer user_data) {
    (void)user_data;
    if (!any_popup_has_focus())
        close_all_popups();
    return G_SOURCE_REMOVE;
}

static void on_popup_focus_leave(GtkEventControllerFocus *ctrl,
                                  gpointer user_data) {
    (void)ctrl; (void)user_data;
    g_idle_add(focus_out_recheck, NULL);
}

/* Attach a focus controller that fires close_all_popups on focus loss. */
static void attach_outside_click_close(GtkWidget *win) {
    GtkEventController *focus = gtk_event_controller_focus_new();
    g_signal_connect(focus, "leave",
                     G_CALLBACK(on_popup_focus_leave), NULL);
    gtk_widget_add_controller(win, focus);
}

/* Move a GtkWindow at the X11 level. GTK4 removed gtk_window_move(); the
   GdkSurface is mapped to a real X11 Window we can reposition with
   XMoveWindow. Must be called after the window has been realized (i.e.
   after gtk_widget_set_visible TRUE).

   The popup is **not** override-redirect — the WM keeps managing it so
   focus tracking still works (focus-out fires when the user clicks
   elsewhere). We tag the window with a stack of EWMH hints that make
   sane WMs (fluxbox, openbox, i3, kwin, mutter) render it like a
   floating menu: above the tray panel, skipped from taskbar/pager,
   no decorations. */
static void x11_move_window(GtkWidget *win, int x, int y) {
    GdkSurface *surface = gtk_native_get_surface(GTK_NATIVE(win));
    if (!surface || !GDK_IS_X11_SURFACE(surface))
        return;
    Window xid = gdk_x11_surface_get_xid(surface);
    GdkDisplay *display = gdk_surface_get_display(surface);
    Display *xdpy = gdk_x11_display_get_xdisplay(GDK_X11_DISPLAY(display));

    /* These calls poke a window the WM may have already destroyed (a popup
       torn down between scheduling and this idle callback). On GDK's Display
       use GDK's own error trap rather than our global handler — push/pop is
       the spec-correct way to make untrapped BadWindow/BadMatch from these
       raw Xlib calls non-fatal, independent of whichever process-global
       handler happens to be installed. */
    gdk_x11_display_error_trap_push(display);

    /* _NET_WM_WINDOW_TYPE_POPUP_MENU: makes fluxbox / openbox / etc
       render the window above panels and skip decorations. Must be
       set before the window is mapped to be honoured by some WMs;
       on already-mapped windows it works for most modern WMs but a
       few need an unmap/map cycle to re-read the property. */
    Atom wm_type        = XInternAtom(xdpy, "_NET_WM_WINDOW_TYPE", False);
    Atom wm_type_popup  = XInternAtom(xdpy, "_NET_WM_WINDOW_TYPE_POPUP_MENU", False);
    XChangeProperty(xdpy, xid, wm_type, XA_ATOM, 32,
                    PropModeReplace, (unsigned char *)&wm_type_popup, 1);

    /* _NET_WM_STATE_ABOVE + SKIP_TASKBAR + SKIP_PAGER. Bundled into
       one property write. */
    Atom wm_state       = XInternAtom(xdpy, "_NET_WM_STATE", False);
    Atom state_above    = XInternAtom(xdpy, "_NET_WM_STATE_ABOVE", False);
    Atom state_skip_tb  = XInternAtom(xdpy, "_NET_WM_STATE_SKIP_TASKBAR", False);
    Atom state_skip_pg  = XInternAtom(xdpy, "_NET_WM_STATE_SKIP_PAGER", False);
    Atom states[3] = { state_above, state_skip_tb, state_skip_pg };
    XChangeProperty(xdpy, xid, wm_state, XA_ATOM, 32,
                    PropModeReplace, (unsigned char *)states, 3);

    XMoveWindow(xdpy, xid, x, y);
    XRaiseWindow(xdpy, xid);

    /* POPUP_MENU windows aren't given keyboard focus by most WMs (the
       spec says they're "menus", which traditionally use a grab rather
       than focus). Without focus GtkEventControllerFocus's leave signal
       never fires, so we'd have no way to notice the user clicking
       elsewhere. Ask the WM to activate us via _NET_ACTIVE_WINDOW
       (source=2 means "pager / pseudo-user request" which most WMs
       honour without timestamp checks). This is safer than calling
       XSetInputFocus directly — that races the X server with the
       not-yet-fully-mapped window and trips BadMatch. */
    Atom net_active = XInternAtom(xdpy, "_NET_ACTIVE_WINDOW", False);
    XClientMessageEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.type         = ClientMessage;
    ev.window       = xid;
    ev.message_type = net_active;
    ev.format       = 32;
    ev.data.l[0]    = 2;            /* source: pager */
    ev.data.l[1]    = CurrentTime;
    XSendEvent(xdpy, DefaultRootWindow(xdpy), False,
               SubstructureRedirectMask | SubstructureNotifyMask,
               (XEvent *)&ev);

    XFlush(xdpy);
    gdk_x11_display_error_trap_pop_ignored(display);
}

/* Forward declaration — submenu buttons need to schedule a child popup. */
static GtkWidget *build_menu_box(xembed_menu_item *items, int count);

typedef struct {
    xembed_menu_item *items;
    int               count;
    GtkWidget        *anchor;  /* the submenu button — used to position the popup */
} submenu_open_data;

static void on_submenu_button_clicked(GtkButton *btn, gpointer user_data) {
    submenu_open_data *sd = (submenu_open_data *)user_data;

    GtkWidget *win = gtk_window_new();
    gtk_window_set_decorated(GTK_WINDOW(win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);

    attach_outside_click_close(win);

    GtkWidget *vbox = build_menu_box(sd->items, sd->count);
    gtk_window_set_child(GTK_WINDOW(win), vbox);

    /* Need the anchor button's position in root coordinates. GTK4
       removed gtk_widget_translate_coordinates(); compute via the
       button's bounds within its native widget plus the native
       surface's screen origin via X11. */
    graphene_rect_t bounds;
    if (!gtk_widget_compute_bounds(GTK_WIDGET(btn),
                                   GTK_WIDGET(gtk_widget_get_native(GTK_WIDGET(btn))),
                                   &bounds)) {
        bounds.origin.x = 0;
        bounds.origin.y = 0;
        bounds.size.width = 0;
        bounds.size.height = 0;
    }
    GdkSurface *anchor_surface =
        gtk_native_get_surface(gtk_widget_get_native(GTK_WIDGET(btn)));
    int ox = 0, oy = 0;
    if (anchor_surface && GDK_IS_X11_SURFACE(anchor_surface)) {
        Window axid = gdk_x11_surface_get_xid(anchor_surface);
        GdkDisplay *display = gdk_surface_get_display(anchor_surface);
        Display *xdpy = gdk_x11_display_get_xdisplay(GDK_X11_DISPLAY(display));
        Window child;
        /* Trap BadWindow in case the anchor's surface is torn down between
           the click and this handler running. */
        gdk_x11_display_error_trap_push(display);
        XTranslateCoordinates(xdpy, axid, DefaultRootWindow(xdpy),
                              0, 0, &ox, &oy, &child);
        gdk_x11_display_error_trap_pop_ignored(display);
    }
    int ax = ox + (int)bounds.origin.x;
    int ay = oy + (int)bounds.origin.y;

    gtk_widget_set_visible(win, TRUE);

    int sw, sh;
    gtk_window_get_default_size(GTK_WINDOW(win), &sw, &sh);
    if (sw <= 0 || sh <= 0) {
        /* default_size returns -1,-1 if never explicitly set; fall back
           to the measured preferred size. */
        GtkRequisition req;
        gtk_widget_get_preferred_size(win, NULL, &req);
        sw = req.width;
        sh = req.height;
    }

    /* The parent popup grows upward from the tray, so submenu items
       sit closer to the bottom of the screen than to the top. Align
       the submenu's BOTTOM to the anchor button's bottom: the popup
       grows upward, level with the row that opened it. */
    int final_x = ax + (int)bounds.size.width;
    int final_y = ay + (int)bounds.size.height - sh;

    /* Horizontal flip against the monitor under the anchor button. */
    GdkDisplay *display = gtk_widget_get_display(win);
    GListModel *monitors = gdk_display_get_monitors(display);
    guint n = g_list_model_get_n_items(monitors);
    for (guint i = 0; i < n; i++) {
        GdkMonitor *m = (GdkMonitor *)g_list_model_get_item(monitors, i);
        GdkRectangle geom;
        gdk_monitor_get_geometry(m, &geom);
        if (ax >= geom.x && ax < geom.x + geom.width &&
            ay >= geom.y && ay < geom.y + geom.height) {
            if (final_x + sw > geom.x + geom.width)
                final_x = ax - sw;          /* flip to the left */
            g_object_unref(m);
            break;
        }
        g_object_unref(m);
    }

    x11_move_window(win, final_x, final_y);
    gtk_window_present(GTK_WINDOW(win));

    submenu_popups = g_list_prepend(submenu_popups, win);
}

/* Build a vbox of GtkWidgets for the supplied items. Used for both the
   top-level popup and each submenu popup. The submenu_open_data attached
   to submenu buttons is freed when the button is destroyed. */
static void on_button_destroy_free_data(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    free(user_data);
}

static GtkWidget *build_menu_box(xembed_menu_item *items, int count) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    for (int i = 0; i < count; i++) {
        xembed_menu_item *mi = &items[i];

        if (mi->is_separator) {
            GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
            gtk_widget_set_margin_top(sep, 2);
            gtk_widget_set_margin_bottom(sep, 2);
            gtk_box_append(GTK_BOX(vbox), sep);
            continue;
        }

        if (mi->is_check) {
            GtkWidget *chk = gtk_check_button_new_with_label(
                mi->label ? mi->label : "");
            gtk_check_button_set_active(GTK_CHECK_BUTTON(chk), mi->checked);
            gtk_widget_set_sensitive(chk, mi->enabled);
            g_signal_connect(chk, "toggled",
                             G_CALLBACK(on_check_toggled),
                             GINT_TO_POINTER(mi->id));
            gtk_box_append(GTK_BOX(vbox), chk);
            continue;
        }

        /* Plain button (leaf) or submenu opener. Show "Label  ▸" for
           submenu folders so users see they're nested. */
        const char *label_text = mi->label ? mi->label : "";
        char *display_label = NULL;
        if (mi->child_count > 0 && mi->children) {
            /* Compose "label  ▸" (BLACK RIGHT-POINTING SMALL TRIANGLE). */
            size_t n = strlen(label_text) + 8;  /* ascii + " ▸" + NUL */
            display_label = (char *)malloc(n);
            snprintf(display_label, n, "%s \xE2\x96\xB8", label_text);
            label_text = display_label;
        }

        GtkWidget *btn = gtk_button_new_with_label(label_text);
        gtk_widget_set_sensitive(btn, mi->enabled);
        gtk_button_set_has_frame(GTK_BUTTON(btn), FALSE);
        GtkWidget *lbl = gtk_button_get_child(GTK_BUTTON(btn));
        if (GTK_IS_LABEL(lbl))
            gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);

        free(display_label);

        if (mi->child_count > 0 && mi->children) {
            submenu_open_data *sd =
                (submenu_open_data *)calloc(1, sizeof(submenu_open_data));
            sd->items   = mi->children;
            sd->count   = mi->child_count;
            sd->anchor  = btn;
            g_signal_connect(btn, "clicked",
                             G_CALLBACK(on_submenu_button_clicked), sd);
            g_signal_connect(btn, "destroy",
                             G_CALLBACK(on_button_destroy_free_data), sd);
        } else {
            g_signal_connect(btn, "clicked",
                             G_CALLBACK(on_button_clicked),
                             GINT_TO_POINTER(mi->id));
        }
        gtk_box_append(GTK_BOX(vbox), btn);
    }

    return vbox;
}

static gboolean popup_menu_idle(gpointer user_data) {
    popup_data *pd = (popup_data *)user_data;

    /* Destroy old top-level (and orphan submenus) before rebuilding. */
    close_all_popups();
    if (popup_win) {
        gtk_window_destroy(GTK_WINDOW(popup_win));
        popup_win = NULL;
    }

    popup_win = gtk_window_new();
    gtk_window_set_decorated(GTK_WINDOW(popup_win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(popup_win), FALSE);

    attach_outside_click_close(popup_win);

    GtkWidget *vbox = build_menu_box(pd->items, pd->count);
    gtk_window_set_child(GTK_WINDOW(popup_win), vbox);

    gtk_widget_set_visible(popup_win, TRUE);

    /* Position the window above the click point (menu grows upward
       from tray). Use measured preferred size — default_size is -1
       until set. */
    GtkRequisition req;
    gtk_widget_get_preferred_size(popup_win, NULL, &req);
    int win_w = req.width;
    int win_h = req.height;

    int final_x = pd->x - win_w / 2;
    int final_y = pd->y - win_h;
    if (final_x < 0) final_x = 0;
    if (final_y < 0) final_y = pd->y;  /* fallback: below click */
    x11_move_window(popup_win, final_x, final_y);

    gtk_window_present(GTK_WINDOW(popup_win));

    /* The vbox+children retain pointers into pd->items (via submenu
       click handlers). free_popup_data() walks the array recursively
       to release labels and children buffers — but we need to keep
       the items alive while the popup is open. Defer the free until
       the popup window is destroyed. */
    g_object_set_data_full(G_OBJECT(popup_win), "popup_data", pd,
                           (GDestroyNotify)free_popup_data);
    return G_SOURCE_REMOVE;
}

/* Recursively deep-copy a Go-supplied items array into freshly-allocated
   C memory. Each label is strdup'd, each children array is calloc'd. */
static xembed_menu_item *copy_items(xembed_menu_item *src, int count) {
    if (count <= 0 || !src) return NULL;
    xembed_menu_item *dst =
        (xembed_menu_item *)calloc(count, sizeof(xembed_menu_item));
    for (int i = 0; i < count; i++) {
        dst[i] = src[i];
        if (src[i].label)
            dst[i].label = strdup(src[i].label);
        if (src[i].child_count > 0 && src[i].children) {
            dst[i].children   = copy_items(src[i].children, src[i].child_count);
            dst[i].child_count = src[i].child_count;
        } else {
            dst[i].children   = NULL;
            dst[i].child_count = 0;
        }
    }
    return dst;
}

void xembed_show_popup_menu(xembed_menu_item *items, int count,
                            xembed_menu_click_cb cb, int x, int y) {
    (void)cb;
    popup_data *pd = (popup_data *)calloc(1, sizeof(popup_data));
    pd->items = copy_items(items, count);
    pd->count = count;
    pd->x = x;
    pd->y = y;

    g_idle_add(popup_menu_idle, pd);
}
