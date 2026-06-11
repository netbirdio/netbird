//go:build linux && !(linux && 386)

package main

// recenterOnShowPredicate returns the predicate WindowManager uses to decide
// whether to re-center its Go-shown windows (main, Settings) on each show.
//
// On Linux this is xembedTrayAvailable: re-centering is needed only in the
// minimal-WM / in-process-XEmbed-tray environment, where the window manager
// neither centers small windows for us nor restores their position across a
// hide -> show round-trip. The predicate is evaluated per show (not once at
// startup) because the XEmbed tray can appear after the UI starts — the panel
// and the autostarted app race at login — and xembedTrayAvailable is a cheap,
// side-effect-free selection-owner probe, fine to call repeatedly.
func recenterOnShowPredicate() func() bool {
	return xembedTrayAvailable
}
