package ipcauth

// IsConsoleUser reports whether a caller is sitting at one of this machine's
// consoles right now.
//
// It is false on a headless machine, which has no seat to sit at, on a
// platform that exposes no console-user lookup at all, and whenever the lookup
// fails. Callers must read that as "cannot confirm" rather than as proof of
// absence. It gates handing out ownership, so a lookup that cannot answer
// withholds a claim, and never grants one.
func IsConsoleUser(id Identity) bool {
	if !id.Known() {
		return false
	}
	return isConsoleUser(id)
}
