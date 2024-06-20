//go:build darwin || dragonfly || netbsd || openbsd

package systemops

import "syscall"

// filterRoutesByFlags - return true if need to ignore such route message because it consists specific flags.
func filterRoutesByFlags(routeMessageFlags int) bool {
	if routeMessageFlags&syscall.RTF_UP == 0 {
		return true
	}

	if routeMessageFlags&(syscall.RTF_REJECT|syscall.RTF_BLACKHOLE|syscall.RTF_WASCLONED) != 0 {
		return true
	}

	return false
}
