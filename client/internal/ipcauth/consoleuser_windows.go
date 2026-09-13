package ipcauth

import (
	"golang.org/x/sys/windows"
)

// activeIdentity returns a synthetic Ideneity for the currently active
// Windows console session.
//
// Returns false when there is no active console session, the session has no
// logged-in user, or any lookup fails.
func activeIdentity() (Identity, bool) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return Identity{}, false
	}

	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return Identity{}, false
	}
	defer token.Close()

	identity, err := identityFromToken(token)
	if err != nil {
		return Identity{}, false
	}

	return identity, true
}
