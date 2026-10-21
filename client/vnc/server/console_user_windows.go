package server

import (
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// wtsSessionInfoEx is WTSSessionInfoEx, the WTSQuerySessionInformation info
// class that reports a session's lock state.
const wtsSessionInfoEx = 25

// WTS_SESSIONSTATE_* from wtsapi32.h. Windows 7 and Server 2008 R2 shipped
// these two inverted; every release the client supports reports lock as 0.
const (
	wtsSessionStateLock   int32 = 0
	wtsSessionStateUnlock int32 = 1
)

// wtsInfoEx mirrors WTSINFOEXW as far as the field we read. The union that
// follows Level holds LARGE_INTEGER members, so it is 8-byte aligned and Level
// is followed by four bytes of padding.
type wtsInfoEx struct {
	Level        uint32
	_            uint32
	SessionID    uint32
	SessionState uint32
	SessionFlags int32
}

// interactiveUserError returns nil when there is a logged-in user session on
// the box who could actually see an approval prompt. It is the guard that keeps
// the prompt failing closed when there is nobody to consent.
func interactiveUserError() error {
	sid := getActiveSessionID()
	if sid == 0 {
		return errNoConsoleUser
	}
	if !wtsSessionHasUser(sid) {
		return errNoConsoleUser
	}

	// A logged-in session can still be locked, and WTSQueryUserName keeps
	// returning the user's name throughout: the earlier check only rules out
	// the login screen, where no session exists yet. While the workstation is
	// locked, Windows shows the Winlogon secure desktop and the prompt renders
	// on Default, so nobody can see or answer it — the request would sit there
	// until it timed out. Refuse up front instead.
	if locked, known := consoleSessionLocked(sid); known && locked {
		return errNoConsoleUser
	}
	return nil
}

// consoleSessionLocked reports whether sessionID is locked. known is false when
// the lock state cannot be determined, in which case the caller keeps its
// previous behaviour and lets the prompt through: an unanswered prompt still
// times out into a denial, so guessing "locked" here would only cost sessions
// on hosts whose lock state is unreadable.
func consoleSessionLocked(sessionID uint32) (locked, known bool) {
	var buf uintptr
	var bytesReturned uint32
	r, _, _ := procWTSQuerySessionInformation.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionID),
		uintptr(wtsSessionInfoEx),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r == 0 || buf == 0 {
		return false, false
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(buf) }()

	if uintptr(bytesReturned) < unsafe.Sizeof(wtsInfoEx{}) {
		log.Debugf("WTSSessionInfoEx returned %d bytes, too short to read the lock state", bytesReturned)
		return false, false
	}
	info := (*wtsInfoEx)(unsafe.Pointer(buf))
	if info.Level != 1 {
		return false, false
	}

	switch info.SessionFlags {
	case wtsSessionStateLock:
		return true, true
	case wtsSessionStateUnlock:
		return false, true
	default:
		// WTS_SESSIONSTATE_UNKNOWN, reported while a session is still settling.
		return false, false
	}
}
