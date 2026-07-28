//go:build linux

package services

/*
#cgo pkg-config: x11
#cgo LDFLAGS: -lX11
#include <X11/Xlib.h>
#include <stdlib.h>

typedef struct CursorPoint {
    int x;
    int y;
    int ok;
} CursorPoint;

// XQueryPointer works on X11 and, via XWayland, on Wayland sessions.
// ok=0 when no X server is reachable.
CursorPoint nbGetCursorPos(void) {
    CursorPoint p = {0, 0, 0};
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) return p;
    Window root = DefaultRootWindow(dpy);
    if (root == 0) { XCloseDisplay(dpy); return p; }
    Window root_return = 0, child_return = 0;
    int root_x = 0, root_y = 0, win_x = 0, win_y = 0;
    unsigned int mask_return = 0;
    if (XQueryPointer(dpy, root, &root_return, &child_return,
                      &root_x, &root_y, &win_x, &win_y, &mask_return)) {
        p.x = root_x;
        p.y = root_y;
        p.ok = 1;
    }
    XCloseDisplay(dpy);
    return p;
}
*/
import "C"

import "github.com/wailsapp/wails/v3/pkg/application"

func getCursorPosition(app *application.App) (application.Point, bool) {
	res := C.nbGetCursorPos()
	if res.ok == 0 {
		return application.Point{}, false
	}
	p := application.Point{X: int(res.x), Y: int(res.y)}
	// X11 root coords are physical pixels; Screen.Bounds is in DIPs.
	if app == nil || app.Screen == nil {
		return p, true
	}
	return app.Screen.PhysicalToDipPoint(p), true
}
