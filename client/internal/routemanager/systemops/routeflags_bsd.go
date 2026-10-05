//go:build darwin || dragonfly || netbsd || openbsd

package systemops

import (
	"strings"

	"golang.org/x/sys/unix"
)

// filterRoutesByFlags returns true if the route message should be ignored based on its flags.
func filterRoutesByFlags(routeMessageFlags int) bool {
	if routeMessageFlags&unix.RTF_UP == 0 {
		return true
	}

	if routeMessageFlags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_WASCLONED) != 0 {
		return true
	}

	return false
}

// formatBSDFlags formats route flags for BSD systems (excludes FreeBSD-specific handling)
func formatBSDFlags(flags int) string {
	var flagStrs []string

	if flags&unix.RTF_UP != 0 {
		flagStrs = append(flagStrs, "U")
	}
	if flags&unix.RTF_GATEWAY != 0 {
		flagStrs = append(flagStrs, "G")
	}
	if flags&unix.RTF_HOST != 0 {
		flagStrs = append(flagStrs, "H")
	}
	if flags&unix.RTF_REJECT != 0 {
		flagStrs = append(flagStrs, "R")
	}
	if flags&unix.RTF_DYNAMIC != 0 {
		flagStrs = append(flagStrs, "D")
	}
	if flags&unix.RTF_MODIFIED != 0 {
		flagStrs = append(flagStrs, "M")
	}
	if flags&unix.RTF_STATIC != 0 {
		flagStrs = append(flagStrs, "S")
	}
	if flags&unix.RTF_LLINFO != 0 {
		flagStrs = append(flagStrs, "L")
	}
	if flags&unix.RTF_LOCAL != 0 {
		flagStrs = append(flagStrs, "l")
	}
	if flags&unix.RTF_BLACKHOLE != 0 {
		flagStrs = append(flagStrs, "B")
	}
	if flags&unix.RTF_CLONING != 0 {
		flagStrs = append(flagStrs, "C")
	}
	if flags&unix.RTF_WASCLONED != 0 {
		flagStrs = append(flagStrs, "W")
	}
	if flags&unix.RTF_PROTO1 != 0 {
		flagStrs = append(flagStrs, "1")
	}
	if flags&unix.RTF_PROTO2 != 0 {
		flagStrs = append(flagStrs, "2")
	}
	if flags&unix.RTF_PROTO3 != 0 {
		flagStrs = append(flagStrs, "3")
	}

	if len(flagStrs) == 0 {
		return "-"
	}
	return strings.Join(flagStrs, "")
}
