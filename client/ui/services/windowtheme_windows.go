package services

import "github.com/wailsapp/wails/v3/pkg/w32"

// Wails assigns w32.AllowDarkModeForWindow only on builds >= 18334 but calls it
// without a nil check when a window requests the Dark theme, crashing older
// builds such as Windows Server 2019 (17763). Those builds still get a dark
// title bar via the pre-20H1 DWM attribute that w32.SetTheme applies, so a
// no-op stub keeps the Dark theme fully working there.
func init() {
	if w32.AllowDarkModeForWindow == nil {
		w32.AllowDarkModeForWindow = func(w32.HWND, bool) uintptr { return 0 }
	}
}
