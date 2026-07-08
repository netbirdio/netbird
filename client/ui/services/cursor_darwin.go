//go:build darwin

package services

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Cocoa -framework AppKit
#import <Cocoa/Cocoa.h>
#import <AppKit/AppKit.h>

typedef struct CursorPoint {
    int x;
    int y;
    int ok;
} CursorPoint;

// NSEvent.mouseLocation is Y-up from primary's bottom-left; flip against
// the primary's frame height so the point matches Wails' Y-down Screen.Bounds.
CursorPoint nbGetCursorPos(void) {
    CursorPoint p = {0, 0, 0};
    NSArray<NSScreen *> *screens = [NSScreen screens];
    if (screens == nil || screens.count == 0) return p;
    NSScreen *primary = [screens firstObject];
    if (primary == nil) return p;
    NSPoint loc = [NSEvent mouseLocation];
    p.x = (int)loc.x;
    p.y = (int)(primary.frame.size.height - loc.y);
    p.ok = 1;
    return p;
}
*/
import "C"

import "github.com/wailsapp/wails/v3/pkg/application"

func getCursorPosition(_ *application.App) (application.Point, bool) {
	res := C.nbGetCursorPos()
	if res.ok == 0 {
		return application.Point{}, false
	}
	return application.Point{X: int(res.x), Y: int(res.y)}, true
}
