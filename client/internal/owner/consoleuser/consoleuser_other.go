//go:build !linux && !darwin && !freebsd && !windows

package consoleuser

// activeUID has no meaning on platforms without a console-user concept
// (ios, android). Returns no-user so TOFU never fires.
func activeUID() (uint32, bool) {
	return 0, false
}
