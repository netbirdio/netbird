package services

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit

#import <AppKit/AppKit.h>

// forced < 0: follow the OS (appearance nil); 0: light; 1: dark.
//
// dispatch_async, not dispatch_sync: the main queue is serial FIFO and callers
// enqueue under Theme.apply's mutex, so the newest theme still lands last. A
// synchronous hop would instead block the main thread while that mutex is held,
// which the bound Theme/Preferences methods can deadlock against.
static void nbSetWindowAppearance(void *nsWindow, int forced) {
	NSWindow *window = (__bridge NSWindow *)nsWindow;
	dispatch_async(dispatch_get_main_queue(), ^{
		if (forced < 0) {
			window.appearance = nil;
		} else {
			NSAppearanceName name = forced == 1 ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua;
			window.appearance = [NSAppearance appearanceNamed:name];
		}
	});
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
// flip, leaving a mismatched border around the webview.
func setWindowAppearance(nsWindow unsafe.Pointer, pref preferences.Theme) {
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
