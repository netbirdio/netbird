package server

import "errors"

// consoleHasInteractiveUser returns true when a user is logged into the
// console (i.e. an Aqua session is active). At the loginwindow there is
// nobody to display an approval prompt to, so callers can decline
// without waiting on the broker.
func consoleHasInteractiveUser() bool {
	if _, err := consoleUserID(); err != nil {
		if errors.Is(err, errNoConsoleUser) {
			return false
		}
		// Unknown error: fail closed so a probe-time glitch does not
		// silently let an unattended console accept VNC sessions.
		return false
	}
	return true
}
