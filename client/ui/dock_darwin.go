//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static int lastDockState = -1;

static void refreshDockPolicy(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        Class cls = NSClassFromString(@"WebviewWindow");
        if (cls == nil) {
            return;
        }
        int visible = 0;
        for (NSWindow *w in [NSApp windows]) {
            if ([w isKindOfClass:cls] && [w isVisible]) {
                visible = 1;
                break;
            }
        }
        if (visible == lastDockState) {
            return;
        }
        lastDockState = visible;

        // Set application to "Regular" and show dock icon (when visible) or to "Accessory" (when hidden)
        if (visible) {
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            [NSApp activateIgnoringOtherApps:YES];
        } else {
            [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        }
    });
}

static int dockObserverInstalled = 0;

static void initDockObserver(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (dockObserverInstalled) {
            return;
        }
        dockObserverInstalled = 1;
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        void (^trigger)(NSNotification *) = ^(NSNotification *_) {
            refreshDockPolicy();
        };

        [nc addObserverForName:NSWindowDidChangeOcclusionStateNotification
                        object:nil
                         queue:nil
                    usingBlock:trigger];
        [nc addObserverForName:NSWindowWillCloseNotification
                        object:nil
                         queue:nil
                    usingBlock:trigger];

        refreshDockPolicy();
    });
}
*/
import "C"

func initDockObserver() {
	C.initDockObserver()
}
