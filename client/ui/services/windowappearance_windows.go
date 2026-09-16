package services

import (
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/w32"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance re-themes a live window's chrome; Wails only does this
// itself on OS flips for SystemDefault windows.
//
// Must run on the UI thread, which Theme.apply guarantees: the uxtheme and
// repaint calls behind w32.SetTheme belong to the window's thread, and hwnd is
// only known live while we hold that thread. Re-dispatching here would let the
// window be destroyed first and hand these writes a reused handle.
//
// dark is the appearance Theme.apply already resolved. Re-reading the OS here
// would let the chrome land on the other side of an OS flip from the window
// background and the webview.
func setWindowAppearance(hwnd unsafe.Pointer, _ preferences.Theme, dark bool) {
	if hwnd == nil || !w32.SupportsThemes() || w32.IsCurrentlyHighContrastMode() {
		return
	}

	h := uintptr(hwnd)
	w32.SetTheme(h, dark)

	// After SetTheme, not before: its menu helper regates dark on the
	// process-level ShouldAppsUseDarkMode and rewrites the per-window opt-in
	// with that gated value, so forcing Dark on a light OS would lose it --
	// and builds below 18985 need the opt-in for the pre-20H1 dark frame. The
	// gated menu theme name is left alone on purpose: these windows carry no
	// native menu, and popup-menu text follows the process policy, so forcing
	// it dark gives dark text on dark.
	if w32.AllowDarkModeForWindow != nil {
		w32.AllowDarkModeForWindow(h, dark)
	}

	chrome := microsoftWindowsLightTheme
	if dark {
		chrome = microsoftWindowsDarkTheme
	}
	if chrome.TitleBarColour != nil {
		w32.SetTitleBarColour(h, *chrome.TitleBarColour)
	}
	if chrome.TitleTextColour != nil {
		w32.SetTitleTextColour(h, *chrome.TitleTextColour)
	}
	if chrome.BorderColour != nil {
		w32.SetBorderColour(h, *chrome.BorderColour)
	}
}
