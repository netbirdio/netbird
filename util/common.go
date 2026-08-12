package util

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/skratchdot/open-golang/open"
)

// OpenBrowser opens the URL in a browser, respecting the BROWSER environment variable.
func OpenBrowser(url string) error {
	if browser := os.Getenv("BROWSER"); browser != "" {
		return exec.Command(browser, url).Start()
	}
	return open.Run(url)
}

// browserSessionEnvVars returns the variables that decide whether OpenBrowser can open a URL:
// BROWSER is the explicit override it honors first, DESKTOP_SESSION and XDG_CURRENT_DESKTOP are
// what xdg-open uses to pick a handler, and DISPLAY / WAYLAND_DISPLAY are what any graphical
// browser it launches needs.
func browserSessionEnvVars() []string {
	return []string{"BROWSER", "DESKTOP_SESSION", "XDG_CURRENT_DESKTOP", "DISPLAY", "WAYLAND_DISPLAY"}
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

	// tty and unspecified sessions have no display; anything else (x11, wayland, mir) does
	switch os.Getenv("XDG_SESSION_TYPE") {
	case "", "tty", "unspecified":
		return false
	default:
		return true
	}
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
