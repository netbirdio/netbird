//go:build darwin && !ios

package main

// bindTrayClick wires the tray icon's left-click handler on macOS.
//
// Before macOS 27 the Wails event-monitor intercepted left-click, temporarily
// set statusItem.menu, and relied on native NSStatusBarButton tracking — without
// firing the action handler. That path broke in macOS 27, so left-click produced
// no response.
//
// With an OnClick handler set, systrayPreClickCallback returns 0 for left-click,
// skipping the broken event-monitor path. The action handler fires and calls
// OpenMenu() → showMenu(), which synthesizes a mouseDown to open the menu.
//
// Right-click already uses this same showMenu path on all macOS versions: Wails'
// applySmartDefaults sets rightClickHandler = ShowMenu when a menu is present and
// no right-click handler is explicitly registered. If right-click opens the menu
// without freezing, left-click via the identical path does too.
//
// History: commit c77e5ce reverted an earlier OnClick→OpenMenu attempt because
// showMenu then blocked the main GCD queue synchronously. The netbirdio/wails
// fork's showMenu now uses dispatch_async, so the action handler returns before
// the blocking mouseDown call, matching the timing of the right-click path that
// already runs without issue.
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.tray.OpenMenu() })
}
