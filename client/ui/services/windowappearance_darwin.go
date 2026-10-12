package services

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit

#import <AppKit/AppKit.h>

// forced < 0: follow the OS (appearance nil); 0: light; 1: dark.
//
// Assigns directly rather than dispatching: Theme.apply already runs this on
// the main thread. Deferring would outlive the caller's check that the window
// is alive, and the __bridge cast does not retain it, so the block could touch
// a freed NSWindow.
static void nbSetWindowAppearance(void *nsWindow, int forced) {
	NSWindow *window = (__bridge NSWindow *)nsWindow;
	if (forced < 0) {
		window.appearance = nil;
	} else {
		NSAppearanceName name = forced == 1 ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua;
		window.appearance = [NSAppearance appearanceNamed:name];
	}
}
*/
import "C"

import (
	"unsafe"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance pins the NSWindow appearance to the forced theme, or
// hands it back to the OS for ThemeSystem. Without this, a window created
// under one OS appearance keeps its dark/light frame after a manual theme
// flip, leaving a mismatched border around the webview. Must run on the main
// thread, which Theme.apply guarantees.
//
// The resolved appearance is unused: for ThemeSystem a nil NSAppearance lets
// AppKit track the OS itself, which cannot drift from a snapshot we took.
func setWindowAppearance(nsWindow unsafe.Pointer, pref preferences.Theme, _ bool) {
	if nsWindow == nil {
		return
	}
	forced := C.int(-1)
	switch pref {
	case preferences.ThemeLight:
		forced = 0
	case preferences.ThemeDark:
		forced = 1
	}
	C.nbSetWindowAppearance(nsWindow, forced)
}
