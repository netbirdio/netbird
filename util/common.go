package util

import (
	"os"
	"os/exec"
	"runtime"
	"slices"

	"github.com/skratchdot/open-golang/open"
)

const (
	// envBrowser overrides the browser OpenBrowser launches
	envBrowser = "BROWSER"
	// envDesktopSession and envXDGCurrentDesktop are what xdg-open uses to pick a handler
	envDesktopSession    = "DESKTOP_SESSION"
	envXDGCurrentDesktop = "XDG_CURRENT_DESKTOP"
	// envDisplay and envWaylandDisplay are what a graphical browser needs to reach a display
	envDisplay        = "DISPLAY"
	envWaylandDisplay = "WAYLAND_DISPLAY"
	// envXDGSessionType names the session kind, e.g. tty, x11 or wayland
	envXDGSessionType = "XDG_SESSION_TYPE"
)

// OpenBrowser opens the URL in a browser, respecting the BROWSER environment variable.
func OpenBrowser(url string) error {
	if browser := os.Getenv(envBrowser); browser != "" {
		return exec.Command(browser, url).Start()
	}
	return open.Run(url)
}

// browserSessionEnvVars returns the variables that decide whether OpenBrowser can open a URL.
// DISPLAY and WAYLAND_DISPLAY are exactly what xdg-open's own has_display() checks, and without
// them it degrades to terminal browsers. BROWSER is the explicit override both xdg-open and
// OpenBrowser honor first. DESKTOP_SESSION and XDG_CURRENT_DESKTOP only tell xdg-open which
// desktop-specific opener to prefer, so they are weaker evidence, kept because the previous
// detection relied on them alone and dropping them would demote sessions that work today.
func browserSessionEnvVars() []string {
	return []string{envDisplay, envWaylandDisplay, envBrowser, envDesktopSession, envXDGCurrentDesktop}
}

// graphicalXDGSessionTypes are the systemd-logind session types that come with a display. The
// other documented values are "tty" and "unspecified"; anything unrecognized is treated as no
// display, so an unknown value picks the device code flow, which works without a browser.
func graphicalXDGSessionTypes() []string {
	return []string{"x11", "wayland", "mir"}
}

// HasGraphicalSession reports whether this process can open a browser and serve a loopback
// redirect back to it. Windows and macOS always can. On Linux and FreeBSD the answer is env
// based, so it only holds for a process started from the graphical session itself: a service
// does not inherit those variables and always reports false, which is why callers running in
// the user's session pass their own answer to the daemon.
func HasGraphicalSession() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		return true
	}

	for _, env := range browserSessionEnvVars() {
		if os.Getenv(env) != "" {
			return true
		}
	}

	return slices.Contains(graphicalXDGSessionTypes(), os.Getenv(envXDGSessionType))
}

// SliceDiff returns the elements in slice `x` that are not in slice `y`
func SliceDiff(x, y []string) []string {
	mapY := make(map[string]struct{}, len(y))
	for _, val := range y {
		mapY[val] = struct{}{}
	}
	var diff []string
	for _, val := range x {
		if _, found := mapY[val]; !found {
			diff = append(diff, val)
		}
	}
	return diff
}

// FileExists returns true if specified file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

/// Bool helpers

// True returns a *bool whose underlying value is true.
func True() *bool {
	t := true
	return &t
}

// False returns a *bool whose underlying value is false.
func False() *bool {
	t := false
	return &t
}

// Return bool representation if the bool pointer is non-nil, otherwise returns false
func ReturnBoolWithDefaultFalse(b *bool) bool {
	if b != nil {
		return *b
	} else {
		return false
	}

}

// Return bool representation if the bool pointer is non-nil, otherwise returns true
func ReturnBoolWithDefaultTrue(b *bool) bool {
	if b != nil {
		return *b
	} else {
		return true
	}

}
