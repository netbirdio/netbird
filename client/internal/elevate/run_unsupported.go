//go:build !windows && !darwin && !linux

package elevate

import "context"

// run reports that this platform has no elevation prompt to drive.
//
// The desktop app is the only caller and is not built for any of these: mobile
// and WASM have no local user to ask, and the FreeBSD client ships without a UI.
// pkexec would be the mechanism there, and run_unix.go is what to widen if that
// changes.
func run(context.Context, string, []string) error {
	return ErrUnavailable
}

func mechanismAvailable() bool {
	return false
}
