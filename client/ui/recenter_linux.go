//go:build linux && !(linux && 386)

package main

import (
	"os"
	"strings"
)

// recenterOnShowPredicate returns the predicate WindowManager uses to decide
// whether to re-center its Go-shown windows (main, Settings) on each show.
//
// Re-centering is needed only on bare WMs (fluxbox, IceWM, twm …) that neither
// place small windows for us nor restore their position across a hide -> show
// round-trip — the same environment the in-process XEmbed tray host serves.
// xembedTrayAvailable (a _NET_SYSTEM_TRAY_S0 selection-owner probe) detects
// that host, but it is NOT a clean proxy for "bare WM": full desktops like
// Cinnamon, MATE, XFCE and LXDE ship a legacy XEmbed systray AND a real
// compositing WM (Muffin/Marco/xfwm4) that places windows itself. On those,
// running the post-show X11 re-center makes the window visibly jump from the
// WM's placement to ours (reported on Cinnamon/Mint/X11). So we additionally
// require that the session does NOT advertise a known full desktop.
//
// Evaluated per show (not once at startup) because the XEmbed tray can appear
// after the UI starts — the panel and the autostarted app race at login — and
// xembedTrayAvailable is a cheap, side-effect-free selection-owner probe.
func recenterOnShowPredicate() func() bool {
	return func() bool {
		return xembedTrayAvailable() && !inFullDesktopEnvironment()
	}
}

// fullDesktopTokens are desktop-environment identifiers whose window manager
// places and restores windows for us. Several also expose a legacy XEmbed
// systray, so they must be excluded from the re-center path explicitly.
// Matched case-insensitively against the colon-separated XDG_CURRENT_DESKTOP /
// DESKTOP_SESSION tokens. Bare WMs leave these unset (or report their own name,
// e.g. "Fluxbox"), which is absent here — so they still re-center.
var fullDesktopTokens = []string{
	"cinnamon", "mate", "xfce", "gnome", "kde", "plasma",
	"lxde", "lxqt", "unity", "budgie", "deepin", "pantheon",
}

// inFullDesktopEnvironment reports whether the session advertises one of the
// known full desktop environments via XDG_CURRENT_DESKTOP or DESKTOP_SESSION.
func inFullDesktopEnvironment() bool {
	for _, env := range []string{"XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"} {
		for _, tok := range strings.Split(os.Getenv(env), ":") {
			tok = strings.ToLower(strings.TrimSpace(tok))
			for _, full := range fullDesktopTokens {
				if strings.Contains(tok, full) {
					return true
				}
			}
		}
	}
	return false
}
