//go:build linux && !(linux && 386)

package main

// recenterOnShowPredicate returns a per-show predicate; re-centering is only
// needed under the minimal-WM / in-process-XEmbed-tray environment, which neither
// centers small windows nor restores position across hide -> show. Evaluated per
// show, not at startup, because the XEmbed tray can appear after the UI starts
// (panel and autostarted app race at login); xembedTrayAvailable is a cheap,
// side-effect-free probe safe to call repeatedly.
func recenterOnShowPredicate() func() bool {
	return xembedTrayAvailable
}
