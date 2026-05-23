package server

// interactiveUserError returns nil when there is a logged-in user session
// on the box. At the lock/login screen WTSQueryUserName is empty, which
// means there is nobody to display an approval prompt to.
func interactiveUserError() error {
	sid := getActiveSessionID()
	if sid == 0 {
		return errNoConsoleUser
	}
	if !wtsSessionHasUser(sid) {
		return errNoConsoleUser
	}
	return nil
}
