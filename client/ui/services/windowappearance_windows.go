package services

import (
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/w32"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance re-themes a live window's chrome; Wails only does this
// itself on OS flips for SystemDefault windows.
func setWindowAppearance(hwnd unsafe.Pointer, pref preferences.Theme) {
	if hwnd == nil || !w32.SupportsThemes() || w32.IsCurrentlyHighContrastMode() {
		return
	}

	var dark bool
	switch pref {
	case preferences.ThemeDark:
		dark = true
	case preferences.ThemeLight:
		dark = false
	default:
		dark = w32.IsCurrentlyDarkMode()
	}

	h := uintptr(hwnd)
	if w32.AllowDarkModeForWindow != nil {
		w32.AllowDarkModeForWindow(h, dark)
	}
	w32.SetTheme(h, dark)

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
