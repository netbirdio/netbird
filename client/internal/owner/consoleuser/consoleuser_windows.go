package consoleuser

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// activeUID returns a synthetic UID (the user SID's RID) for the currently
// active Windows console session. The owner package treats UIDs as opaque
// uint32 identifiers; on Windows we use the user account RID, which is stable
// per-account on a given machine.
//
// Returns (0, false) when there is no active console session, the session has
// no logged-in user, or any lookup fails.
func activeUID() (uint32, bool) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return 0, false
	}

	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return 0, false
	}
	defer token.Close()

	user, err := tokenUserSID(token)
	if err != nil || user == nil {
		return 0, false
	}

	subCount := user.SubAuthorityCount()
	if subCount == 0 {
		return 0, false
	}
	rid := user.SubAuthority(uint32(subCount) - 1)
	if rid == 0 {
		return 0, false
	}
	return rid, true
}

// tokenUserSID returns the user SID associated with the given access token.
func tokenUserSID(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenUser, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}

	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenUser, &buf[0], size, &size); err != nil {
		return nil, err
	}

	tu := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	return tu.User.Sid, nil
}
