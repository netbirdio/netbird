package ipcauth

import (
	"fmt"
	"os"
	"syscall"
)

// isConsoleUser reports whether id is logged into the FreeBSD console.
// FreeBSD's vt(4) chowns the active virtual terminal device to the logged-in
// user, so a non-root owner of any /dev/ttyvN reliably identifies a console
// user.
//
// We scan /dev/ttyv0../dev/ttyv9. Network ptys (pts) are intentionally not
// considered: SSH'd users are not "at the console".
func isConsoleUser(id Identity) bool {
	// A SID belongs to a Windows principal and has no uid to compare.
	if id.IsWindows() {
		return false
	}

	// A root-owned ttyv is an unclaimed terminal rather than a root login, so
	// uid 0 never matches. A root caller is privileged anyway and does not
	// reach ownership checks through here.
	if id.UID == 0 {
		return false
	}

	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("/dev/ttyv%d", i)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if st.Uid == id.UID {
			return true
		}
	}

	return false
}
