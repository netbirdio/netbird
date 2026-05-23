package server

// interactiveUserError returns nil when a user is logged into the console
// (i.e. an Aqua session is active). At the loginwindow there is nobody to
// display an approval prompt to, so callers can decline without waiting on
// the broker. Any error (including errNoConsoleUser) is treated as decline.
func interactiveUserError() error {
	_, err := consoleUserID()
	return err
}
