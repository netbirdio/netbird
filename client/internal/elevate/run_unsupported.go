//go:build !windows && !darwin && !linux && !freebsd

package elevate

import "context"

// run reports that this platform has no elevation prompt to drive. Mobile and
// WASM builds have no local user to ask in the first place.
func run(context.Context, string, []string) error {
	return ErrUnavailable
}

func mechanismAvailable() bool {
	return false
}
