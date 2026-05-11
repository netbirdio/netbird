#include "xembed_tray_linux.h"

#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <cairo/cairo-xlib.h>
#include <cairo/cairo.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SYSTEM_TRAY_REQUEST_DOCK 0
#define XEMBED_MAPPED            (1 << 0)

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

/* --- GTK3 popup window menu support --- */

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
   top-level window. */
static void close_all_popups(void) {
    for (GList *l = submenu_popups; l; l = l->next) {
        gtk_widget_destroy(GTK_WIDGET(l->data));
    }
    g_list_free(submenu_popups);
    submenu_popups = NULL;

    if (popup_win) {
        gtk_widget_hide(popup_win);
    }
}

static void on_button_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    int id = GPOINTER_TO_INT(user_data);
    close_all_popups();
    goMenuItemClicked(id);
}

static void on_check_toggled(GtkToggleButton *btn, gpointer user_data) {
    (void)btn;
    int id = GPOINTER_TO_INT(user_data);
    close_all_popups();
    goMenuItemClicked(id);
}

/* When any popup loses focus we want to close the entire popup tree —
   unless focus moved to another window we own (e.g. opening a submenu).
   focus-out fires before the corresponding focus-in on the new window,
   so we defer the check to an idle callback: by then any sibling popup
   has had a chance to grab focus. If none of our windows still has
   toplevel focus, the user clicked outside the menu tree → tear down. */
static gboolean any_popup_has_focus(void) {
    if (popup_win && gtk_window_has_toplevel_focus(GTK_WINDOW(popup_win)))
        return TRUE;
    for (GList *l = submenu_popups; l; l = l->next) {
        if (gtk_window_has_toplevel_focus(GTK_WINDOW(l->data)))
            return TRUE;
    }
    return FALSE;
}

static gboolean focus_out_recheck(gpointer user_data) {
    (void)user_data;
    if (!any_popup_has_focus()) {
        close_all_popups();
    }
    return G_SOURCE_REMOVE;
}

static gboolean on_popup_focus_out(GtkWidget *widget, GdkEvent *event,
                                    gpointer user_data) {
    (void)widget; (void)event; (void)user_data;
    g_idle_add(focus_out_recheck, NULL);
    return FALSE;
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

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_type_hint(GTK_WINDOW(win), GDK_WINDOW_TYPE_HINT_POPUP_MENU);
    gtk_window_set_decorated(GTK_WINDOW(win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_set_skip_taskbar_hint(GTK_WINDOW(win), TRUE);
    gtk_window_set_skip_pager_hint(GTK_WINDOW(win), TRUE);
    gtk_window_set_keep_above(GTK_WINDOW(win), TRUE);

    g_signal_connect(win, "focus-out-event",
                     G_CALLBACK(on_popup_focus_out), NULL);

    GtkWidget *vbox = build_menu_box(sd->items, sd->count);
    gtk_container_add(GTK_CONTAINER(win), vbox);

    /* GtkButton has no native GdkWindow of its own — gtk_widget_get_window
       returns the parent popup's window. To get the button's screen-space
       position we read the popup origin (ox, oy) and add the button's
       allocation within the popup. */
    gint ox, oy;
    gdk_window_get_origin(gtk_widget_get_window(GTK_WIDGET(btn)), &ox, &oy);
    GtkAllocation alloc;
    gtk_widget_get_allocation(GTK_WIDGET(btn), &alloc);
    int ax = ox + alloc.x;
    int ay = oy + alloc.y;

    gtk_widget_show_all(win);
    gint sw, sh;
    gtk_window_get_size(GTK_WINDOW(win), &sw, &sh);

    /* The parent popup grows upward from the tray, so submenu items
       sit closer to the bottom of the screen than to the top. Align
       the submenu's BOTTOM to the anchor button's bottom: the popup
       grows upward, level with the row that opened it. Don't clamp
       to the monitor top — that would re-position the submenu next
       to an unrelated sibling row above the anchor. */
    int final_x = ax + alloc.width;
    int final_y = ay + alloc.height - sh;

    /* Horizontal flip against the monitor under the anchor button. */
    GdkDisplay *display = gtk_widget_get_display(win);
    GdkMonitor *monitor = gdk_display_get_monitor_at_point(display, ax, ay);
    if (monitor) {
        GdkRectangle geom;
        gdk_monitor_get_geometry(monitor, &geom);
        if (final_x + sw > geom.x + geom.width)
            final_x = ax - sw;                        /* flip to the left */
    }

    gtk_window_move(GTK_WINDOW(win), final_x, final_y);
    gtk_window_present(GTK_WINDOW(win));

    submenu_popups = g_list_prepend(submenu_popups, win);
}

/* Build a vbox of GtkWidgets for the supplied items. Used for both the
   top-level popup and each submenu popup. The submenu_open_data attached
   to submenu buttons is freed when the submenu_popups list is cleared
   (we use the button's "destroy" signal). */
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
            gtk_box_pack_start(GTK_BOX(vbox), sep, FALSE, FALSE, 2);
            continue;
        }

        if (mi->is_check) {
            GtkWidget *chk = gtk_check_button_new_with_label(
                mi->label ? mi->label : "");
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk), mi->checked);
            gtk_widget_set_sensitive(chk, mi->enabled);
            g_signal_connect(chk, "toggled",
                             G_CALLBACK(on_check_toggled),
                             GINT_TO_POINTER(mi->id));
            gtk_box_pack_start(GTK_BOX(vbox), chk, FALSE, FALSE, 0);
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
        gtk_button_set_relief(GTK_BUTTON(btn), GTK_RELIEF_NONE);
        GtkWidget *lbl = gtk_bin_get_child(GTK_BIN(btn));
        if (lbl) gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);

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
        gtk_box_pack_start(GTK_BOX(vbox), btn, FALSE, FALSE, 0);
    }

    return vbox;
}

static gboolean popup_menu_idle(gpointer user_data) {
    popup_data *pd = (popup_data *)user_data;

    /* Destroy old top-level (and orphan submenus) before rebuilding. */
    close_all_popups();
    if (popup_win) {
        gtk_widget_destroy(popup_win);
        popup_win = NULL;
    }

    popup_win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_type_hint(GTK_WINDOW(popup_win),
                             GDK_WINDOW_TYPE_HINT_POPUP_MENU);
    gtk_window_set_decorated(GTK_WINDOW(popup_win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(popup_win), FALSE);
    gtk_window_set_skip_taskbar_hint(GTK_WINDOW(popup_win), TRUE);
    gtk_window_set_skip_pager_hint(GTK_WINDOW(popup_win), TRUE);
    gtk_window_set_keep_above(GTK_WINDOW(popup_win), TRUE);

    /* Close on focus loss. */
    g_signal_connect(popup_win, "focus-out-event",
                     G_CALLBACK(on_popup_focus_out), NULL);

    GtkWidget *vbox = build_menu_box(pd->items, pd->count);
    gtk_container_add(GTK_CONTAINER(popup_win), vbox);

    gtk_widget_show_all(popup_win);

    /* Position the window above the click point (menu grows upward from tray). */
    gint win_w, win_h;
    gtk_window_get_size(GTK_WINDOW(popup_win), &win_w, &win_h);
    int final_x = pd->x - win_w / 2;
    int final_y = pd->y - win_h;
    if (final_x < 0) final_x = 0;
    if (final_y < 0) final_y = pd->y;  /* fallback: below click */
    gtk_window_move(GTK_WINDOW(popup_win), final_x, final_y);

    /* Grab focus so focus-out-event works. */
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
