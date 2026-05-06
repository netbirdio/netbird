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

/* The popup window, reused across invocations. */
static GtkWidget *popup_win = NULL;

typedef struct {
    xembed_menu_item  *items;
    int                count;
    int                x, y;
} popup_data;

static void free_popup_data(popup_data *pd) {
    if (!pd) return;
    for (int i = 0; i < pd->count; i++)
        free((void *)pd->items[i].label);
    free(pd->items);
    free(pd);
}

static void on_button_clicked(GtkButton *btn, gpointer user_data) {
    int id = GPOINTER_TO_INT(user_data);
    if (popup_win)
        gtk_widget_hide(popup_win);
    goMenuItemClicked(id);
}

static void on_check_toggled(GtkToggleButton *btn, gpointer user_data) {
    int id = GPOINTER_TO_INT(user_data);
    if (popup_win)
        gtk_widget_hide(popup_win);
    goMenuItemClicked(id);
}

static gboolean on_popup_focus_out(GtkWidget *widget, GdkEvent *event,
                                    gpointer user_data) {
    gtk_widget_hide(widget);
    return FALSE;
}

static gboolean popup_menu_idle(gpointer user_data) {
    popup_data *pd = (popup_data *)user_data;

    /* Destroy old popup if it exists. */
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

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(popup_win), vbox);

    for (int i = 0; i < pd->count; i++) {
        xembed_menu_item *mi = &pd->items[i];

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
        } else {
            GtkWidget *btn = gtk_button_new_with_label(
                mi->label ? mi->label : "");
            gtk_widget_set_sensitive(btn, mi->enabled);
            gtk_button_set_relief(GTK_BUTTON(btn), GTK_RELIEF_NONE);
            /* Left-align label. */
            GtkWidget *label = gtk_bin_get_child(GTK_BIN(btn));
            if (label)
                gtk_label_set_xalign(GTK_LABEL(label), 0.0);
            g_signal_connect(btn, "clicked",
                             G_CALLBACK(on_button_clicked),
                             GINT_TO_POINTER(mi->id));
            gtk_box_pack_start(GTK_BOX(vbox), btn, FALSE, FALSE, 0);
        }
    }

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

    free_popup_data(pd);
    return G_SOURCE_REMOVE;
}

void xembed_show_popup_menu(xembed_menu_item *items, int count,
                            xembed_menu_click_cb cb, int x, int y) {
    (void)cb;
    popup_data *pd = (popup_data *)calloc(1, sizeof(popup_data));
    pd->items = (xembed_menu_item *)calloc(count, sizeof(xembed_menu_item));
    pd->count = count;
    pd->x = x;
    pd->y = y;

    for (int i = 0; i < count; i++) {
        pd->items[i] = items[i];
        if (items[i].label)
            pd->items[i].label = strdup(items[i].label);
    }

    g_idle_add(popup_menu_idle, pd);
}
