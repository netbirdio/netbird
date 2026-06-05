//go:build !linux || (linux && 386)

package main

// recenterOnShowPredicate returns nil off Linux (and on the cgo-less linux/386
// build): macOS and Windows window managers center windows and restore their
// position across hide -> show themselves, so the Go-side re-centering that
// the minimal-WM Linux path needs would only fight a window the user moved.
// A nil predicate makes WindowManager.centerWhenReady a no-op.
func recenterOnShowPredicate() func() bool {
	return nil
}
