package server

// consoleHasInteractiveUser returns true when there is a logged-in user
// session on the box. At the lock/login screen WTSQueryUserName is empty,
// which means there is nobody to display an approval prompt to. Callers
// should decline without waiting on the broker in that case.
func consoleHasInteractiveUser() bool {
	sid := getActiveSessionID()
	if sid == 0 {
		return false
	}
	return wtsSessionHasUser(sid)
}
