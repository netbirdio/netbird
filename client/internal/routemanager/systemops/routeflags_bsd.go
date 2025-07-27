//go:build darwin || dragonfly || netbsd || openbsd

package systemops

import (
	"strings"
	"syscall"
)

// filterRoutesByFlags returns true if the route message should be ignored based on its flags.
func filterRoutesByFlags(routeMessageFlags int) bool {
	if routeMessageFlags&syscall.RTF_UP == 0 {
		return true
	}

	if routeMessageFlags&(syscall.RTF_REJECT|syscall.RTF_BLACKHOLE|syscall.RTF_WASCLONED) != 0 {
		return true
	}

	return false
}

// formatBSDFlags formats route flags for BSD systems (excludes FreeBSD-specific handling)
func formatBSDFlags(flags int) string {
	var flagStrs []string

	if flags&syscall.RTF_UP != 0 {
		flagStrs = append(flagStrs, "U")
	}
	if flags&syscall.RTF_GATEWAY != 0 {
		flagStrs = append(flagStrs, "G")
	}
	if flags&syscall.RTF_HOST != 0 {
		flagStrs = append(flagStrs, "H")
	}
	if flags&syscall.RTF_REJECT != 0 {
		flagStrs = append(flagStrs, "R")
	}
	if flags&syscall.RTF_DYNAMIC != 0 {
		flagStrs = append(flagStrs, "D")
	}
	if flags&syscall.RTF_MODIFIED != 0 {
		flagStrs = append(flagStrs, "M")
	}
	if flags&syscall.RTF_STATIC != 0 {
		flagStrs = append(flagStrs, "S")
	}
	if flags&syscall.RTF_LLINFO != 0 {
		flagStrs = append(flagStrs, "L")
	}
	if flags&syscall.RTF_LOCAL != 0 {
		flagStrs = append(flagStrs, "l")
	}
	if flags&syscall.RTF_BLACKHOLE != 0 {
		flagStrs = append(flagStrs, "B")
	}
	if flags&syscall.RTF_CLONING != 0 {
		flagStrs = append(flagStrs, "C")
	}
	if flags&syscall.RTF_WASCLONED != 0 {
		flagStrs = append(flagStrs, "W")
	}

	if len(flagStrs) == 0 {
		return "-"
	}
	return strings.Join(flagStrs, "")
}
