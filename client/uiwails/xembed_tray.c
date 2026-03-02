#include "xembed_tray.h"

#include <X11/Xatom.h>
#include <X11/Xutil.h>
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

/* Find a 32-bit TrueColor ARGB visual on the given screen. */
static Visual *find_argb_visual(Display *dpy, int screen, int *out_depth) {
    XVisualInfo tmpl;
    tmpl.screen = screen;
    tmpl.depth  = 32;
    tmpl.class  = TrueColor;
    int ninfo = 0;
    XVisualInfo *vi = XGetVisualInfo(dpy,
        VisualScreenMask | VisualDepthMask | VisualClassMask,
        &tmpl, &ninfo);
    if (!vi || ninfo == 0)
        return NULL;

    Visual *vis = vi[0].visual;
    *out_depth  = vi[0].depth;
    XFree(vi);
    return vis;
}

/* Try to get a 32-bit ARGB visual for the tray icon.
   First checks _NET_SYSTEM_TRAY_VISUAL on the tray manager window;
   if not set, searches for any 32-bit TrueColor visual on the screen. */
static Visual *get_tray_visual(Display *dpy, int screen, Window tray_mgr,
                                int *out_depth) {
    Atom atom = XInternAtom(dpy, "_NET_SYSTEM_TRAY_VISUAL", False);
    Atom actual_type;
    int actual_format;
    unsigned long nitems, bytes_after;
    unsigned char *prop = NULL;

    if (XGetWindowProperty(dpy, tray_mgr, atom, 0, 1, False,
                           XA_VISUALID, &actual_type, &actual_format,
                           &nitems, &bytes_after, &prop) == Success &&
        prop && nitems == 1) {
        VisualID vid = (VisualID)(*(unsigned long *)prop);
        XFree(prop);

        /* Look up the visual by ID. */
        XVisualInfo tmpl;
        tmpl.visualid = vid;
        tmpl.screen = screen;
        int ninfo = 0;
        XVisualInfo *vi = XGetVisualInfo(dpy,
            VisualIDMask | VisualScreenMask, &tmpl, &ninfo);
        if (vi && ninfo > 0) {
            Visual *vis = vi[0].visual;
            *out_depth = vi[0].depth;
            XFree(vi);
            return vis;
        }
    } else {
        if (prop) XFree(prop);
    }

    /* Tray didn't advertise a visual — find one ourselves. */
    return find_argb_visual(dpy, screen, out_depth);
}

Window xembed_create_icon(Display *dpy, int screen, int size,
                           Window tray_mgr) {
    Window root = RootWindow(dpy, screen);

    /* Try to use the tray's advertised ARGB visual for transparency. */
    int depth = 0;
    Visual *vis = get_tray_visual(dpy, screen, tray_mgr, &depth);

    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.event_mask = ButtonPressMask | StructureNotifyMask | ExposureMask;
    unsigned long mask = CWEventMask;

    if (vis && depth == 32) {
        /* 32-bit visual: create our own colormap and set a transparent bg. */
        attrs.colormap = XCreateColormap(dpy, root, vis, AllocNone);
        attrs.background_pixel = 0;  /* fully transparent */
        attrs.border_pixel = 0;
        mask |= CWColormap | CWBackPixel | CWBorderPixel;
    } else {
        /* Fallback: use default visual. */
        vis = CopyFromParent;
        depth = CopyFromParent;
        attrs.background_pixel = 0;
        mask |= CWBackPixel;
    }

    Window win = XCreateWindow(
        dpy, root,
        0, 0, size, size,
        0,                          /* border width */
        depth,
        InputOutput,
        vis,
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

    /* Query the window's actual visual and depth so we draw correctly
       even when using a 32-bit ARGB visual for transparency. */
    XWindowAttributes wa;
    if (!XGetWindowAttributes(dpy, icon_win, &wa))
        return;

    int depth  = wa.depth;
    Visual *vis = wa.visual;

    /* Clear the window to transparent before drawing. */
    XClearWindow(dpy, icon_win);

    /* Allocate buffer for the scaled image in native X11 format (32bpp). */
    unsigned int *buf = (unsigned int *)calloc(win_size * win_size,
                                               sizeof(unsigned int));
    if (!buf)
        return;

    /* Nearest-neighbor scale from source ARGB [A,R,G,B] bytes to native uint32. */
    int x, y;
    for (y = 0; y < win_size; y++) {
        int src_y = y * img_h / win_size;
        if (src_y >= img_h) src_y = img_h - 1;
        for (x = 0; x < win_size; x++) {
            int src_x = x * img_w / win_size;
            if (src_x >= img_w) src_x = img_w - 1;

            int idx = (src_y * img_w + src_x) * 4;
            unsigned char a = data[idx + 0];
            unsigned char r = data[idx + 1];
            unsigned char g = data[idx + 2];
            unsigned char b = data[idx + 3];

            /* Pre-multiply alpha for correct compositing on 32-bit visuals. */
            if (a == 0) {
                buf[y * win_size + x] = 0;
            } else if (a == 255) {
                buf[y * win_size + x] = ((unsigned int)a << 24) |
                                        ((unsigned int)r << 16) |
                                        ((unsigned int)g << 8)  |
                                        ((unsigned int)b);
            } else {
                unsigned int pr = (unsigned int)r * a / 255;
                unsigned int pg = (unsigned int)g * a / 255;
                unsigned int pb = (unsigned int)b * a / 255;
                buf[y * win_size + x] = ((unsigned int)a << 24) |
                                        (pr << 16) | (pg << 8) | pb;
            }
        }
    }

    XImage *img = XCreateImage(dpy, vis, depth, ZPixmap, 0,
                               (char *)buf, win_size, win_size,
                               32, 0);
    if (!img) {
        free(buf);
        return;
    }

    GC gc = XCreateGC(dpy, icon_win, 0, NULL);
    XPutImage(dpy, icon_win, gc, img, 0, 0, 0, 0, win_size, win_size);
    XFreeGC(dpy, gc);

    /* XDestroyImage frees the data pointer (buf) for us. */
    XDestroyImage(img);
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
