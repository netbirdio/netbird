package ipcauth

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	devDir = "/dev"

	// vtPrefix names the virtual terminals vt(4) publishes. How many there are
	// is a kernel constant rather than a fixed number, and past the tenth they
	// are not spelled in decimal: the unit is rendered in base 32, so the one
	// after ttyv9 is ttyva.
	vtPrefix = "ttyv"
)

// isConsoleUser reports whether id is logged into the FreeBSD console.
// FreeBSD's vt(4) chowns the virtual terminal device to the user logged in on
// it, so a non-root owner of any /dev/ttyv* reliably identifies a console user.
//
// Network ptys (pts) are intentionally not considered: SSH'd users are not "at
// the console".
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

	entries, err := os.ReadDir(devDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		name := entry.Name()
		suffix, ok := strings.CutPrefix(name, vtPrefix)
		if !ok || suffix == "" {
			continue
		}
		fi, err := os.Stat(filepath.Join(devDir, name))
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
