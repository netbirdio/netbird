package ipcauth

import (
	"golang.org/x/sys/windows"
)

// isConsoleUser reports whether id is the user logged into the active Windows
// console session.
//
// Returns false when there is no active console session, the session has no
// logged-in user, or any lookup fails.
func isConsoleUser(id Identity) bool {
	// A caller with no SID is not a Windows principal and has nothing to
	// compare against the console session's token.
	if !id.IsWindows() {
		return false
	}

	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return false
	}

	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return false
	}
	defer token.Close()

	console, err := identityFromToken(token)
	if err != nil {
		return false
	}

	// The console session's token and the caller's token carry the same SID for
	// the same account, so the SID is what the two identities share. Elevation
	// is deliberately not compared: whether the caller's shell is elevated says
	// nothing about who is sitting at the console.
	return console.SID != "" && console.SID == id.SID
}
